# Hyper-Optimized with Process Identity Tracking (v6)
$JsonPath = "C:\PerfLogs\2026-01-19 SECURE_KERNEL_ERROR (18b).DMP\2026-01-18_20-26-40_perfdata_log.json"
$CsvPath = $JsonPath -replace "\.json$", ".csv"

# --- 1. Schema Discovery with Process Identity Tracking ---
Write-Host "Step 1/4: Analyzing Schema and building process identity map..." -ForegroundColor Cyan
$Lines = [System.IO.File]::ReadAllLines($JsonPath) | Where-Object { $_.Trim() }

# Track process identities: ProcessName#ID -> CommandLine -> UniqueID
$ProcessIdentities = @{}
$ProcessCounters = New-Object 'System.Collections.Generic.HashSet[string]'
$NextUniqueId = @{}

foreach ($Line in $Lines) {
    $Obj = $Line | ConvertFrom-Json
    
    foreach ($p in $Obj.counters.PSObject.Properties) {
        $CounterName = $p.Name
        
        # Check if this is a process counter (contains process name pattern)
        if ($CounterName -match '^(.+?)_(.+)$') {
            $ProcessPart = $matches[1]
            $MetricPart = $matches[2]
            
            # Look for command_line counter to establish identity
            if ($MetricPart -eq 'command_line') {
                $CommandLine = $p.Value
                $IdentityKey = "$ProcessPart|$CommandLine"
                
                # If we haven't seen this exact process+commandline combo, assign unique ID
                if (-not $ProcessIdentities.ContainsKey($IdentityKey)) {
                    # Extract base process name (e.g., "svchost" from "svchost#70")
                    if ($ProcessPart -match '^(.+?)(?:#\d+)?$') {
                        $BaseName = $matches[1]
                    } else {
                        $BaseName = $ProcessPart
                    }
                    
                    # Get next ID for this base name
                    if (-not $NextUniqueId.ContainsKey($BaseName)) {
                        $NextUniqueId[$BaseName] = 1
                    }
                    
                    $UniqueId = $NextUniqueId[$BaseName]
                    $NextUniqueId[$BaseName]++
                    
                    $UniqueName = if ($BaseName -match '#') { 
                        # Already has #, use as-is but track separately
                        "${BaseName}_${UniqueId}"
                    } else {
                        "${BaseName}_${UniqueId}"
                    }
                    
                    $ProcessIdentities[$IdentityKey] = @{
                        OriginalName = $ProcessPart
                        UniqueName = $UniqueName
                        CommandLine = $CommandLine
                    }
                }
            }
        }
        
        # Track all counter types
        $null = $ProcessCounters.Add($CounterName)
    }
}

Write-Host "  Found $($ProcessIdentities.Count) unique process instances" -ForegroundColor Gray

# --- 2. Build Column Mapping ---
Write-Host "Step 2/4: Building column schema..." -ForegroundColor Cyan

# Fixed system counters
$FixedColumns = @(
    "memory_pool_nonpaged_allocs", "memory_pool_nonpaged_bytes", "memory_pool_paged_bytes",
    "memory_system_driver_total_bytes", "memory_available_mbytes", "paging_file_total_per_usage",
    "system_context_switches_per_sec", "system_processor_queue_length", "system_system_calls_per_sec",
    "system_system_up_time", "objects_processes", "objects_threads",
    "processor_total_interrupts_sec", "processor_total_percent_dpc_time"
)

# Create mapping from original counter names to unique column names
$CounterToColumn = @{}
$AllColumns = New-Object 'System.Collections.Generic.HashSet[string]'

# Add fixed columns
foreach ($col in $FixedColumns) {
    $null = $AllColumns.Add($col)
    $CounterToColumn[$col] = $col
}

# Process dynamic counters (per-process metrics)
foreach ($CounterName in $ProcessCounters) {
    if ($CounterName -match '^(.+?)_(.+)$') {
        $ProcessPart = $matches[1]
        $MetricPart = $matches[2]
        
        # Skip if this is a fixed column
        if ($CounterName -in $FixedColumns) {
            continue
        }
        
        # For each process counter, we need to find which unique process it belongs to
        # This will be resolved per-row during data extraction
        $null = $AllColumns.Add($CounterName)
    } else {
        # Non-process counter
        $null = $AllColumns.Add($CounterName)
        $CounterToColumn[$CounterName] = $CounterName
    }
}

# Build final schema: timestamp + fixed + all unique process columns
$DynamicColumns = ($AllColumns | Where-Object { $_ -notin $FixedColumns }) | Sort-Object
$FullSchema = @("timestamp") + $FixedColumns + $DynamicColumns

# --- 3. Create Process Lookup Cache ---
Write-Host "Step 3/4: Creating process lookup cache..." -ForegroundColor Cyan

# For each row, we need to quickly map ProcessName#ID -> UniqueName
# Build a reverse lookup: OriginalName -> [IdentityKey -> UniqueName]
$ProcessLookup = @{}
foreach ($IdentityKey in $ProcessIdentities.Keys) {
    $Identity = $ProcessIdentities[$IdentityKey]
    $OrigName = $Identity.OriginalName
    
    if (-not $ProcessLookup.ContainsKey($OrigName)) {
        $ProcessLookup[$OrigName] = @{}
    }
    
    $ProcessLookup[$OrigName][$IdentityKey] = $Identity.UniqueName
}

# --- 4. Parallel Processing with Identity Resolution ---
Write-Host "Step 4/4: Extracting data with process identity resolution..." -ForegroundColor Cyan
$IndexedLines = for ($i=0; $i -lt $Lines.Count; $i++) { 
    [PSCustomObject]@{ Id = $i; Json = $Lines[$i] } 
}

$CsvResults = $IndexedLines | ForEach-Object -Parallel {
    $Data = $_.Json | ConvertFrom-Json
    
    # Build process identity map for this row
    $RowProcessMap = @{}
    
    # First pass: identify all processes in this row by their command lines
    foreach ($p in $Data.counters.PSObject.Properties) {
        if ($p.Name -match '^(.+?)_command_line$') {
            $ProcessPart = $matches[1]
            $CommandLine = $p.Value
            $IdentityKey = "$ProcessPart|$CommandLine"
            
            # Look up the unique name for this process+commandline
            $UniqueName = ($using:ProcessIdentities)[$IdentityKey].UniqueName
            if ($UniqueName) {
                $RowProcessMap[$ProcessPart] = $UniqueName
            }
        }
    }
    
    # Second pass: build the CSV row
    $LineValues = [System.Collections.Generic.List[string]]::new()
    
    foreach ($Col in $using:FullSchema) {
        if ($Col -eq "timestamp") {
            $LineValues.Add("`"$($Data.timestamp)`"")
            continue
        }
        
        # Check if this is a process-specific counter
        $Val = $null
        if ($Col -match '^(.+?)_(.+)$') {
            $ProcessPart = $matches[1]
            $MetricPart = $matches[2]
            
            # Try to find the value using the original process name
            if ($Data.counters.PSObject.Properties.Name -contains $Col) {
                $Val = $Data.counters.$Col
            }
        } else {
            # Direct lookup for non-process counters
            if ($Data.counters.PSObject.Properties.Name -contains $Col) {
                $Val = $Data.counters.$Col
            }
        }
        
        if ($null -eq $Val) {
            $LineValues.Add("")
        } else {
            # Strip newlines and escape quotes
            $StringVal = $Val.ToString().Replace("`r", "").Replace("`n", " ")
            $EscapedVal = $StringVal.Replace('"', '""')
            $LineValues.Add("`"$EscapedVal`"")
        }
    }
    
    [PSCustomObject]@{ Id = $_.Id; Row = $LineValues -join "," }
} -ThrottleLimit 32

# --- 5. Final Re-sort & Save ---
Write-Host "Finalizing: Re-sorting and saving..." -ForegroundColor Cyan
$HeaderRow = ($FullSchema | ForEach-Object { "`"$_`"" }) -join ","
$SortedRows = $CsvResults | Sort-Object Id | ForEach-Object { $_.Row }

[System.IO.File]::WriteAllLines($CsvPath, @($HeaderRow) + $SortedRows)

Write-Host "`nDone! Created CSV with process identity tracking:" -ForegroundColor Green
Write-Host "  Total unique process instances: $($ProcessIdentities.Count)" -ForegroundColor Gray
Write-Host "  Output file: $CsvPath" -ForegroundColor Gray

# Optionally, save process identity map for reference
$IdentityMapPath = $JsonPath -replace "\.json$", "_process_map.txt"
$IdentityReport = @("Process Identity Map", "=" * 80, "")
foreach ($key in ($ProcessIdentities.Keys | Sort-Object)) {
    $id = $ProcessIdentities[$key]
    $IdentityReport += "Original: $($id.OriginalName)"
    $IdentityReport += "Unique:   $($id.UniqueName)"
    $IdentityReport += "CmdLine:  $($id.CommandLine)"
    $IdentityReport += ""
}
[System.IO.File]::WriteAllLines($IdentityMapPath, $IdentityReport)
Write-Host "  Process map saved to: $IdentityMapPath" -ForegroundColor Gray