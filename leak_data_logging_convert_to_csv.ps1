# Performance Log JSON to CSV with Process Identity Tracking (v7)
#
# ERROR: at least one file has been incorrectly split eg. wudfhost#1 has been split into three processes but only two have a different comamnd line.
#
# How It Works:
# First Pass: Scans all JSON to find __command_line counters, builds identity map
# Schema Build: Creates columns for each unique process + all their metrics
# Data Extraction: For each row, looks up process by command line, maps to correct unique column
# Output: Clean CSV with stable column names

$JsonPath = "C:\PerfLogs\2026-01-19 SECURE_KERNEL_ERROR (18b).DMP\2026-01-18_20-26-40_perfdata_log.json"
$CsvPath = $JsonPath -replace "\.json$", ".csv"

# --- 1. First Pass: Build Process Identity Map ---
Write-Host "Step 1/4: Scanning for unique process instances..." -ForegroundColor Cyan
$Lines = [System.IO.File]::ReadAllLines($JsonPath) | Where-Object { $_.Trim() }

# Track: ProcessName#ID + CommandLine -> Unique identifier
$ProcessIdentities = @{}
$ProcessCounter = @{}  # Track count per base process name
$AllCounters = New-Object 'System.Collections.Generic.HashSet[string]'

foreach ($Line in $Lines) {
    $Obj = $Line | ConvertFrom-Json
    
    # Temporary storage for command lines in this row
    $RowCommandLines = @{}
    
    # First pass: collect all command_line values
    foreach ($prop in $Obj.counters.PSObject.Properties) {
        $CounterName = $prop.Name
        $null = $AllCounters.Add($CounterName)
        
        # Format: __arcspeed_process_svchost#41__command_line
        if ($CounterName -match '^__\w+_process_(.+?)__command_line

Write-Host "  Found $($ProcessIdentities.Count) unique process instances" -ForegroundColor Gray

# --- 2. Build Column Schema ---
Write-Host "Step 2/4: Building column schema..." -ForegroundColor Cyan

# Fixed system counters (after stripping __arcspeed_ prefix)
$FixedColumns = @(
    "memory_pool_nonpaged_allocs", "memory_pool_nonpaged_bytes", "memory_pool_paged_bytes",
    "memory_system_driver_total_bytes", "memory_available_mbytes", "paging_file_total_per_usage",
    "system_context_switches_per_sec", "system_processor_queue_length", "system_system_calls_per_sec",
    "system_system_up_time", "objects_processes", "objects_threads",
    "processor__total__interrupts_sec", "processor__total__percent_dpc_time"
)

# Build set of all unique columns we need
$FinalColumns = New-Object 'System.Collections.Generic.HashSet[string]'

# Add fixed columns
foreach ($col in $FixedColumns) {
    $null = $FinalColumns.Add($col)
}

# For each process identity, create columns for all their metrics
$ProcessMetrics = New-Object 'System.Collections.Generic.HashSet[string]'

foreach ($CounterName in $AllCounters) {
    # Strip __arcspeed_ prefix
    $CleanName = $CounterName -replace '^__\w+_', ''
    
    # Check if it's a process counter: process_NAME__metric
    if ($CleanName -match '^process_(.+?)__(.+)$') {
        $ProcessNameWithId = $matches[1]  # e.g., "svchost#41"
        $Metric = $matches[2]              # e.g., "handle_count"
        
        $null = $ProcessMetrics.Add($Metric)
    } else {
        # Non-process counter (system, memory, etc.)
        $null = $FinalColumns.Add($CleanName)
    }
}

# Now add columns for each unique process
foreach ($Identity in $ProcessIdentities.Values) {
    $UniqueName = $Identity.UniqueName
    
    foreach ($Metric in $ProcessMetrics) {
        $null = $FinalColumns.Add("process_${UniqueName}_${Metric}")
    }
}

# Sort columns: timestamp + fixed + sorted process columns
$DynamicColumns = ($FinalColumns | Where-Object { $_ -notin $FixedColumns }) | Sort-Object
$FullSchema = @("timestamp") + $FixedColumns + $DynamicColumns

Write-Host "  Total columns: $($FullSchema.Count)" -ForegroundColor Gray

# --- 3. Build Lookup Tables ---
Write-Host "Step 3/4: Building lookup tables..." -ForegroundColor Cyan

# Create reverse mapping: OriginalName -> IdentityKey lookup
# This helps us quickly find the right unique name when processing each row
$OriginalToIdentityKeys = @{}
foreach ($IdentityKey in $ProcessIdentities.Keys) {
    $Identity = $ProcessIdentities[$IdentityKey]
    $OrigName = $Identity.OriginalName
    
    if (-not $OriginalToIdentityKeys.ContainsKey($OrigName)) {
        $OriginalToIdentityKeys[$OrigName] = @()
    }
    
    $OriginalToIdentityKeys[$OrigName] += $IdentityKey
}

# --- 4. Parallel Processing ---
Write-Host "Step 4/4: Extracting data (parallel processing)..." -ForegroundColor Cyan
$IndexedLines = for ($i=0; $i -lt $Lines.Count; $i++) { 
    [PSCustomObject]@{ Id = $i; Json = $Lines[$i] } 
}

$CsvResults = $IndexedLines | ForEach-Object -Parallel {
    $Data = $_.Json | ConvertFrom-Json
    
    # Build mapping for this row: OriginalName -> UniqueName
    $RowProcessMap = @{}
    
    # First, identify all processes in this row by their command lines
    foreach ($prop in $Data.counters.PSObject.Properties) {
        $CounterName = $prop.Name
        
        # Match: __arcspeed_process_svchost#41__command_line
        if ($CounterName -match '^__\w+_process_(.+?)__command_line
    
    # Build the CSV row
    $RowData = @{}
    
    # Extract all counter values
    foreach ($prop in $Data.counters.PSObject.Properties) {
        $CounterName = $prop.Name
        $Value = $prop.Value
        
        # Strip __arcspeed_ prefix
        $CleanName = $CounterName -replace '^__\w+_', ''
        
        # Check if it's a process counter
        if ($CleanName -match '^process_(.+?)__(.+)$') {
            $ProcessNameWithId = $matches[1]
            $Metric = $matches[2]
            
            # Map to unique name
            $UniqueName = $RowProcessMap[$ProcessNameWithId]
            
            if ($UniqueName) {
                $FinalColumnName = "process_${UniqueName}_${Metric}"
                $RowData[$FinalColumnName] = $Value
            }
        } else {
            # Non-process counter
            $RowData[$CleanName] = $Value
        }
    }
    
    # Build CSV line
    $LineValues = [System.Collections.Generic.List[string]]::new()
    
    foreach ($Col in $using:FullSchema) {
        if ($Col -eq "timestamp") {
            $LineValues.Add("`"$($Data.timestamp)`"")
            continue
        }
        
        $Val = $RowData[$Col]
        
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

# --- 5. Save CSV ---
Write-Host "Finalizing: Saving CSV..." -ForegroundColor Cyan
$HeaderRow = ($FullSchema | ForEach-Object { "`"$_`"" }) -join ","
$SortedRows = $CsvResults | Sort-Object Id | ForEach-Object { $_.Row }

[System.IO.File]::WriteAllLines($CsvPath, @($HeaderRow) + $SortedRows)

# --- 6. Save Process Identity Map ---
$IdentityMapPath = $JsonPath -replace "\.json$", "_process_map.txt"
$IdentityLines = New-Object System.Collections.Generic.List[string]

$IdentityLines.Add("Process Identity Map")
$IdentityLines.Add("=" * 80)
$IdentityLines.Add("")
$IdentityLines.Add("This file shows how process instances were mapped to unique column names.")
$IdentityLines.Add("Windows can reuse process IDs, so the same 'svchost#70' might represent")
$IdentityLines.Add("different processes at different times based on their command line.")
$IdentityLines.Add("")
$IdentityLines.Add("=" * 80)
$IdentityLines.Add("")

foreach ($IdentityKey in ($ProcessIdentities.Keys | Sort-Object)) {
    $Identity = $ProcessIdentities[$IdentityKey]
    $IdentityLines.Add("Original Name: $($Identity.OriginalName)")
    $IdentityLines.Add("Unique Name:   $($Identity.UniqueName)")
    $IdentityLines.Add("Command Line:  $($Identity.CommandLine)")
    $IdentityLines.Add("-" * 80)
    $IdentityLines.Add("")
}

[System.IO.File]::WriteAllLines($IdentityMapPath, $IdentityLines.ToArray())

Write-Host "`nDone! CSV created with process identity tracking:" -ForegroundColor Green
Write-Host "  Unique process instances: $($ProcessIdentities.Count)" -ForegroundColor Gray
Write-Host "  Total columns: $($FullSchema.Count)" -ForegroundColor Gray
Write-Host "  CSV file: $CsvPath" -ForegroundColor Cyan
Write-Host "  Process map: $IdentityMapPath" -ForegroundColor Cyan

# Show sample of process mappings
Write-Host "`nSample process mappings (first 5):" -ForegroundColor Yellow
$ProcessIdentities.Values | Select-Object -First 5 | ForEach-Object {
    Write-Host "  $($_.OriginalName) -> $($_.UniqueName)" -ForegroundColor Gray
}) {
            $ProcessNameWithId = $matches[1]  # e.g., "svchost#41" or "chrome#5"
            $CommandLine = $prop.Value
            
            # Normalize command line: treat empty, null, or "<unavailable>" as the same
            if ([string]::IsNullOrWhiteSpace($CommandLine) -or $CommandLine -eq "<unavailable>") {
                $CommandLine = "<unavailable>"
            }
            
            $RowCommandLines[$ProcessNameWithId] = $CommandLine
            
            # Create identity key: ProcessName#ID|CommandLine
            $IdentityKey = "$ProcessNameWithId|$CommandLine"
            
            if (-not $ProcessIdentities.ContainsKey($IdentityKey)) {
                # Extract base name (e.g., "svchost" from "svchost#41")
                if ($ProcessNameWithId -match '^(.+?)(?:#\d+)?

Write-Host "  Found $($ProcessIdentities.Count) unique process instances" -ForegroundColor Gray

# --- 2. Build Column Schema ---
Write-Host "Step 2/4: Building column schema..." -ForegroundColor Cyan

# Fixed system counters (after stripping __arcspeed_ prefix)
$FixedColumns = @(
    "memory_pool_nonpaged_allocs", "memory_pool_nonpaged_bytes", "memory_pool_paged_bytes",
    "memory_system_driver_total_bytes", "memory_available_mbytes", "paging_file_total_per_usage",
    "system_context_switches_per_sec", "system_processor_queue_length", "system_system_calls_per_sec",
    "system_system_up_time", "objects_processes", "objects_threads",
    "processor__total__interrupts_sec", "processor__total__percent_dpc_time"
)

# Build set of all unique columns we'll need
$FinalColumns = New-Object 'System.Collections.Generic.HashSet[string]'

# Add fixed columns
foreach ($col in $FixedColumns) {
    $null = $FinalColumns.Add($col)
}

# For each process identity, create columns for all their metrics
$ProcessMetrics = New-Object 'System.Collections.Generic.HashSet[string]'

foreach ($CounterName in $AllCounters) {
    # Strip __arcspeed_ prefix
    $CleanName = $CounterName -replace '^__\w+_', ''
    
    # Check if it's a process counter: process_NAME__metric
    if ($CleanName -match '^process_(.+?)__(.+)$') {
        $ProcessNameWithId = $matches[1]  # e.g., "svchost#41"
        $Metric = $matches[2]              # e.g., "handle_count"
        
        $null = $ProcessMetrics.Add($Metric)
    } else {
        # Non-process counter (system, memory, etc.)
        $null = $FinalColumns.Add($CleanName)
    }
}

# Now add columns for each unique process
foreach ($Identity in $ProcessIdentities.Values) {
    $UniqueName = $Identity.UniqueName
    
    foreach ($Metric in $ProcessMetrics) {
        $null = $FinalColumns.Add("process_${UniqueName}_${Metric}")
    }
}

# Sort columns: timestamp + fixed + sorted process columns
$DynamicColumns = ($FinalColumns | Where-Object { $_ -notin $FixedColumns }) | Sort-Object
$FullSchema = @("timestamp") + $FixedColumns + $DynamicColumns

Write-Host "  Total columns: $($FullSchema.Count)" -ForegroundColor Gray

# --- 3. Build Lookup Tables ---
Write-Host "Step 3/4: Building lookup tables..." -ForegroundColor Cyan

# Create reverse mapping: OriginalName -> IdentityKey lookup
# This helps us quickly find the right unique name when processing each row
$OriginalToIdentityKeys = @{}
foreach ($IdentityKey in $ProcessIdentities.Keys) {
    $Identity = $ProcessIdentities[$IdentityKey]
    $OrigName = $Identity.OriginalName
    
    if (-not $OriginalToIdentityKeys.ContainsKey($OrigName)) {
        $OriginalToIdentityKeys[$OrigName] = @()
    }
    
    $OriginalToIdentityKeys[$OrigName] += $IdentityKey
}

# --- 4. Parallel Processing ---
Write-Host "Step 4/4: Extracting data (parallel processing)..." -ForegroundColor Cyan
$IndexedLines = for ($i=0; $i -lt $Lines.Count; $i++) { 
    [PSCustomObject]@{ Id = $i; Json = $Lines[$i] } 
}

$CsvResults = $IndexedLines | ForEach-Object -Parallel {
    $Data = $_.Json | ConvertFrom-Json
    
    # Build mapping for this row: OriginalName -> UniqueName
    $RowProcessMap = @{}
    
    # First, identify all processes in this row by their command lines
    foreach ($prop in $Data.counters.PSObject.Properties) {
        $CounterName = $prop.Name
        
        # Match: __arcspeed_process_svchost#41__command_line
        if ($CounterName -match '^__\w+_process_(.+?)__command_line$') {
            $ProcessNameWithId = $matches[1]
            $CommandLine = $prop.Value
            
            if ($CommandLine) {
                $IdentityKey = "$ProcessNameWithId|$CommandLine"
                $Identity = ($using:ProcessIdentities)[$IdentityKey]
                
                if ($Identity) {
                    $RowProcessMap[$ProcessNameWithId] = $Identity.UniqueName
                }
            }
        }
    }
    
    # Build the CSV row
    $RowData = @{}
    
    # Extract all counter values
    foreach ($prop in $Data.counters.PSObject.Properties) {
        $CounterName = $prop.Name
        $Value = $prop.Value
        
        # Strip __arcspeed_ prefix
        $CleanName = $CounterName -replace '^__\w+_', ''
        
        # Check if it's a process counter
        if ($CleanName -match '^process_(.+?)__(.+)$') {
            $ProcessNameWithId = $matches[1]
            $Metric = $matches[2]
            
            # Map to unique name
            $UniqueName = $RowProcessMap[$ProcessNameWithId]
            
            if ($UniqueName) {
                $FinalColumnName = "process_${UniqueName}_${Metric}"
                $RowData[$FinalColumnName] = $Value
            }
        } else {
            # Non-process counter
            $RowData[$CleanName] = $Value
        }
    }
    
    # Build CSV line
    $LineValues = [System.Collections.Generic.List[string]]::new()
    
    foreach ($Col in $using:FullSchema) {
        if ($Col -eq "timestamp") {
            $LineValues.Add("`"$($Data.timestamp)`"")
            continue
        }
        
        $Val = $RowData[$Col]
        
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

# --- 5. Save CSV ---
Write-Host "Finalizing: Saving CSV..." -ForegroundColor Cyan
$HeaderRow = ($FullSchema | ForEach-Object { "`"$_`"" }) -join ","
$SortedRows = $CsvResults | Sort-Object Id | ForEach-Object { $_.Row }

[System.IO.File]::WriteAllLines($CsvPath, @($HeaderRow) + $SortedRows)

# --- 6. Save Process Identity Map ---
$IdentityMapPath = $JsonPath -replace "\.json$", "_process_map.txt"
$IdentityLines = New-Object System.Collections.Generic.List[string]

$IdentityLines.Add("Process Identity Map")
$IdentityLines.Add("=" * 80)
$IdentityLines.Add("")
$IdentityLines.Add("This file shows how process instances were mapped to unique column names.")
$IdentityLines.Add("Windows can reuse process IDs, so the same 'svchost#70' might represent")
$IdentityLines.Add("different processes at different times based on their command line.")
$IdentityLines.Add("")
$IdentityLines.Add("=" * 80)
$IdentityLines.Add("")

foreach ($IdentityKey in ($ProcessIdentities.Keys | Sort-Object)) {
    $Identity = $ProcessIdentities[$IdentityKey]
    $IdentityLines.Add("Original Name: $($Identity.OriginalName)")
    $IdentityLines.Add("Unique Name:   $($Identity.UniqueName)")
    $IdentityLines.Add("Command Line:  $($Identity.CommandLine)")
    $IdentityLines.Add("-" * 80)
    $IdentityLines.Add("")
}

[System.IO.File]::WriteAllLines($IdentityMapPath, $IdentityLines.ToArray())

Write-Host "`nDone! CSV created with process identity tracking:" -ForegroundColor Green
Write-Host "  Unique process instances: $($ProcessIdentities.Count)" -ForegroundColor Gray
Write-Host "  Total columns: $($FullSchema.Count)" -ForegroundColor Gray
Write-Host "  CSV file: $CsvPath" -ForegroundColor Cyan
Write-Host "  Process map: $IdentityMapPath" -ForegroundColor Cyan

# Show sample of process mappings
Write-Host "`nSample process mappings (first 5):" -ForegroundColor Yellow
$ProcessIdentities.Values | Select-Object -First 5 | ForEach-Object {
    Write-Host "  $($_.OriginalName) -> $($_.UniqueName)" -ForegroundColor Gray
}) {
                    $BaseName = $matches[1]
                } else {
                    $BaseName = $ProcessNameWithId
                }
                
                # Increment counter for this base name
                if (-not $ProcessCounter.ContainsKey($BaseName)) {
                    $ProcessCounter[$BaseName] = 1
                } else {
                    $ProcessCounter[$BaseName]++
                }
                
                $UniqueId = $ProcessCounter[$BaseName]
                
                $ProcessIdentities[$IdentityKey] = @{
                    OriginalName = $ProcessNameWithId
                    UniqueName = "${BaseName}_${UniqueId}"
                    BaseName = $BaseName
                    CommandLine = $CommandLine
                }
            }
        }
    }
}

Write-Host "  Found $($ProcessIdentities.Count) unique process instances" -ForegroundColor Gray

# --- 2. Build Column Schema ---
Write-Host "Step 2/4: Building column schema..." -ForegroundColor Cyan

# Fixed system counters (after stripping __arcspeed_ prefix)
$FixedColumns = @(
    "memory_pool_nonpaged_allocs", "memory_pool_nonpaged_bytes", "memory_pool_paged_bytes",
    "memory_system_driver_total_bytes", "memory_available_mbytes", "paging_file_total_per_usage",
    "system_context_switches_per_sec", "system_processor_queue_length", "system_system_calls_per_sec",
    "system_system_up_time", "objects_processes", "objects_threads",
    "processor__total__interrupts_sec", "processor__total__percent_dpc_time"
)

# Build set of all unique columns we'll need
$FinalColumns = New-Object 'System.Collections.Generic.HashSet[string]'

# Add fixed columns
foreach ($col in $FixedColumns) {
    $null = $FinalColumns.Add($col)
}

# For each process identity, create columns for all their metrics
$ProcessMetrics = New-Object 'System.Collections.Generic.HashSet[string]'

foreach ($CounterName in $AllCounters) {
    # Strip __arcspeed_ prefix
    $CleanName = $CounterName -replace '^__\w+_', ''
    
    # Check if it's a process counter: process_NAME__metric
    if ($CleanName -match '^process_(.+?)__(.+)$') {
        $ProcessNameWithId = $matches[1]  # e.g., "svchost#41"
        $Metric = $matches[2]              # e.g., "handle_count"
        
        $null = $ProcessMetrics.Add($Metric)
    } else {
        # Non-process counter (system, memory, etc.)
        $null = $FinalColumns.Add($CleanName)
    }
}

# Now add columns for each unique process
foreach ($Identity in $ProcessIdentities.Values) {
    $UniqueName = $Identity.UniqueName
    
    foreach ($Metric in $ProcessMetrics) {
        $null = $FinalColumns.Add("process_${UniqueName}_${Metric}")
    }
}

# Sort columns: timestamp + fixed + sorted process columns
$DynamicColumns = ($FinalColumns | Where-Object { $_ -notin $FixedColumns }) | Sort-Object
$FullSchema = @("timestamp") + $FixedColumns + $DynamicColumns

Write-Host "  Total columns: $($FullSchema.Count)" -ForegroundColor Gray

# --- 3. Build Lookup Tables ---
Write-Host "Step 3/4: Building lookup tables..." -ForegroundColor Cyan

# Create reverse mapping: OriginalName -> IdentityKey lookup
# This helps us quickly find the right unique name when processing each row
$OriginalToIdentityKeys = @{}
foreach ($IdentityKey in $ProcessIdentities.Keys) {
    $Identity = $ProcessIdentities[$IdentityKey]
    $OrigName = $Identity.OriginalName
    
    if (-not $OriginalToIdentityKeys.ContainsKey($OrigName)) {
        $OriginalToIdentityKeys[$OrigName] = @()
    }
    
    $OriginalToIdentityKeys[$OrigName] += $IdentityKey
}

# --- 4. Parallel Processing ---
Write-Host "Step 4/4: Extracting data (parallel processing)..." -ForegroundColor Cyan
$IndexedLines = for ($i=0; $i -lt $Lines.Count; $i++) { 
    [PSCustomObject]@{ Id = $i; Json = $Lines[$i] } 
}

$CsvResults = $IndexedLines | ForEach-Object -Parallel {
    $Data = $_.Json | ConvertFrom-Json
    
    # Build mapping for this row: OriginalName -> UniqueName
    $RowProcessMap = @{}
    
    # First, identify all processes in this row by their command lines
    foreach ($prop in $Data.counters.PSObject.Properties) {
        $CounterName = $prop.Name
        
        # Match: __arcspeed_process_svchost#41__command_line
        if ($CounterName -match '^__\w+_process_(.+?)__command_line$') {
            $ProcessNameWithId = $matches[1]
            $CommandLine = $prop.Value
            
            if ($CommandLine) {
                $IdentityKey = "$ProcessNameWithId|$CommandLine"
                $Identity = ($using:ProcessIdentities)[$IdentityKey]
                
                if ($Identity) {
                    $RowProcessMap[$ProcessNameWithId] = $Identity.UniqueName
                }
            }
        }
    }
    
    # Build the CSV row
    $RowData = @{}
    
    # Extract all counter values
    foreach ($prop in $Data.counters.PSObject.Properties) {
        $CounterName = $prop.Name
        $Value = $prop.Value
        
        # Strip __arcspeed_ prefix
        $CleanName = $CounterName -replace '^__\w+_', ''
        
        # Check if it's a process counter
        if ($CleanName -match '^process_(.+?)__(.+)$') {
            $ProcessNameWithId = $matches[1]
            $Metric = $matches[2]
            
            # Map to unique name
            $UniqueName = $RowProcessMap[$ProcessNameWithId]
            
            if ($UniqueName) {
                $FinalColumnName = "process_${UniqueName}_${Metric}"
                $RowData[$FinalColumnName] = $Value
            }
        } else {
            # Non-process counter
            $RowData[$CleanName] = $Value
        }
    }
    
    # Build CSV line
    $LineValues = [System.Collections.Generic.List[string]]::new()
    
    foreach ($Col in $using:FullSchema) {
        if ($Col -eq "timestamp") {
            $LineValues.Add("`"$($Data.timestamp)`"")
            continue
        }
        
        $Val = $RowData[$Col]
        
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

# --- 5. Save CSV ---
Write-Host "Finalizing: Saving CSV..." -ForegroundColor Cyan
$HeaderRow = ($FullSchema | ForEach-Object { "`"$_`"" }) -join ","
$SortedRows = $CsvResults | Sort-Object Id | ForEach-Object { $_.Row }

[System.IO.File]::WriteAllLines($CsvPath, @($HeaderRow) + $SortedRows)

# --- 6. Save Process Identity Map ---
$IdentityMapPath = $JsonPath -replace "\.json$", "_process_map.txt"
$IdentityLines = New-Object System.Collections.Generic.List[string]

$IdentityLines.Add("Process Identity Map")
$IdentityLines.Add("=" * 80)
$IdentityLines.Add("")
$IdentityLines.Add("This file shows how process instances were mapped to unique column names.")
$IdentityLines.Add("Windows can reuse process IDs, so the same 'svchost#70' might represent")
$IdentityLines.Add("different processes at different times based on their command line.")
$IdentityLines.Add("")
$IdentityLines.Add("=" * 80)
$IdentityLines.Add("")

foreach ($IdentityKey in ($ProcessIdentities.Keys | Sort-Object)) {
    $Identity = $ProcessIdentities[$IdentityKey]
    $IdentityLines.Add("Original Name: $($Identity.OriginalName)")
    $IdentityLines.Add("Unique Name:   $($Identity.UniqueName)")
    $IdentityLines.Add("Command Line:  $($Identity.CommandLine)")
    $IdentityLines.Add("-" * 80)
    $IdentityLines.Add("")
}

[System.IO.File]::WriteAllLines($IdentityMapPath, $IdentityLines.ToArray())

Write-Host "`nDone! CSV created with process identity tracking:" -ForegroundColor Green
Write-Host "  Unique process instances: $($ProcessIdentities.Count)" -ForegroundColor Gray
Write-Host "  Total columns: $($FullSchema.Count)" -ForegroundColor Gray
Write-Host "  CSV file: $CsvPath" -ForegroundColor Cyan
Write-Host "  Process map: $IdentityMapPath" -ForegroundColor Cyan

# Show sample of process mappings
Write-Host "`nSample process mappings (first 5):" -ForegroundColor Yellow
$ProcessIdentities.Values | Select-Object -First 5 | ForEach-Object {
    Write-Host "  $($_.OriginalName) -> $($_.UniqueName)" -ForegroundColor Gray
}) {
            $ProcessNameWithId = $matches[1]
            $CommandLine = $prop.Value
            
            # Normalize command line
            if ([string]::IsNullOrWhiteSpace($CommandLine) -or $CommandLine -eq "<unavailable>") {
                $CommandLine = "<unavailable>"
            }
            
            $IdentityKey = "$ProcessNameWithId|$CommandLine"
            $Identity = ($using:ProcessIdentities)[$IdentityKey]
            
            if ($Identity) {
                $RowProcessMap[$ProcessNameWithId] = $Identity.UniqueName
            }
        }
    }
    
    # Build the CSV row
    $RowData = @{}
    
    # Extract all counter values
    foreach ($prop in $Data.counters.PSObject.Properties) {
        $CounterName = $prop.Name
        $Value = $prop.Value
        
        # Strip __arcspeed_ prefix
        $CleanName = $CounterName -replace '^__\w+_', ''
        
        # Check if it's a process counter
        if ($CleanName -match '^process_(.+?)__(.+)$') {
            $ProcessNameWithId = $matches[1]
            $Metric = $matches[2]
            
            # Map to unique name
            $UniqueName = $RowProcessMap[$ProcessNameWithId]
            
            if ($UniqueName) {
                $FinalColumnName = "process_${UniqueName}_${Metric}"
                $RowData[$FinalColumnName] = $Value
            }
        } else {
            # Non-process counter
            $RowData[$CleanName] = $Value
        }
    }
    
    # Build CSV line
    $LineValues = [System.Collections.Generic.List[string]]::new()
    
    foreach ($Col in $using:FullSchema) {
        if ($Col -eq "timestamp") {
            $LineValues.Add("`"$($Data.timestamp)`"")
            continue
        }
        
        $Val = $RowData[$Col]
        
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

# --- 5. Save CSV ---
Write-Host "Finalizing: Saving CSV..." -ForegroundColor Cyan
$HeaderRow = ($FullSchema | ForEach-Object { "`"$_`"" }) -join ","
$SortedRows = $CsvResults | Sort-Object Id | ForEach-Object { $_.Row }

[System.IO.File]::WriteAllLines($CsvPath, @($HeaderRow) + $SortedRows)

# --- 6. Save Process Identity Map ---
$IdentityMapPath = $JsonPath -replace "\.json$", "_process_map.txt"
$IdentityLines = New-Object System.Collections.Generic.List[string]

$IdentityLines.Add("Process Identity Map")
$IdentityLines.Add("=" * 80)
$IdentityLines.Add("")
$IdentityLines.Add("This file shows how process instances were mapped to unique column names.")
$IdentityLines.Add("Windows can reuse process IDs, so the same 'svchost#70' might represent")
$IdentityLines.Add("different processes at different times based on their command line.")
$IdentityLines.Add("")
$IdentityLines.Add("=" * 80)
$IdentityLines.Add("")

foreach ($IdentityKey in ($ProcessIdentities.Keys | Sort-Object)) {
    $Identity = $ProcessIdentities[$IdentityKey]
    $IdentityLines.Add("Original Name: $($Identity.OriginalName)")
    $IdentityLines.Add("Unique Name:   $($Identity.UniqueName)")
    $IdentityLines.Add("Command Line:  $($Identity.CommandLine)")
    $IdentityLines.Add("-" * 80)
    $IdentityLines.Add("")
}

[System.IO.File]::WriteAllLines($IdentityMapPath, $IdentityLines.ToArray())

Write-Host "`nDone! CSV created with process identity tracking:" -ForegroundColor Green
Write-Host "  Unique process instances: $($ProcessIdentities.Count)" -ForegroundColor Gray
Write-Host "  Total columns: $($FullSchema.Count)" -ForegroundColor Gray
Write-Host "  CSV file: $CsvPath" -ForegroundColor Cyan
Write-Host "  Process map: $IdentityMapPath" -ForegroundColor Cyan

# Show sample of process mappings
Write-Host "`nSample process mappings (first 5):" -ForegroundColor Yellow
$ProcessIdentities.Values | Select-Object -First 5 | ForEach-Object {
    Write-Host "  $($_.OriginalName) -> $($_.UniqueName)" -ForegroundColor Gray
}) {
            $ProcessNameWithId = $matches[1]  # e.g., "svchost#41" or "chrome#5"
            $CommandLine = $prop.Value
            
            # Normalize command line: treat empty, null, or "<unavailable>" as the same
            if ([string]::IsNullOrWhiteSpace($CommandLine) -or $CommandLine -eq "<unavailable>") {
                $CommandLine = "<unavailable>"
            }
            
            $RowCommandLines[$ProcessNameWithId] = $CommandLine
            
            # Create identity key: ProcessName#ID|CommandLine
            $IdentityKey = "$ProcessNameWithId|$CommandLine"
            
            if (-not $ProcessIdentities.ContainsKey($IdentityKey)) {
                # Extract base name (e.g., "svchost" from "svchost#41")
                if ($ProcessNameWithId -match '^(.+?)(?:#\d+)?

Write-Host "  Found $($ProcessIdentities.Count) unique process instances" -ForegroundColor Gray

# --- 2. Build Column Schema ---
Write-Host "Step 2/4: Building column schema..." -ForegroundColor Cyan

# Fixed system counters (after stripping __arcspeed_ prefix)
$FixedColumns = @(
    "memory_pool_nonpaged_allocs", "memory_pool_nonpaged_bytes", "memory_pool_paged_bytes",
    "memory_system_driver_total_bytes", "memory_available_mbytes", "paging_file_total_per_usage",
    "system_context_switches_per_sec", "system_processor_queue_length", "system_system_calls_per_sec",
    "system_system_up_time", "objects_processes", "objects_threads",
    "processor__total__interrupts_sec", "processor__total__percent_dpc_time"
)

# Build set of all unique columns we'll need
$FinalColumns = New-Object 'System.Collections.Generic.HashSet[string]'

# Add fixed columns
foreach ($col in $FixedColumns) {
    $null = $FinalColumns.Add($col)
}

# For each process identity, create columns for all their metrics
$ProcessMetrics = New-Object 'System.Collections.Generic.HashSet[string]'

foreach ($CounterName in $AllCounters) {
    # Strip __arcspeed_ prefix
    $CleanName = $CounterName -replace '^__\w+_', ''
    
    # Check if it's a process counter: process_NAME__metric
    if ($CleanName -match '^process_(.+?)__(.+)$') {
        $ProcessNameWithId = $matches[1]  # e.g., "svchost#41"
        $Metric = $matches[2]              # e.g., "handle_count"
        
        $null = $ProcessMetrics.Add($Metric)
    } else {
        # Non-process counter (system, memory, etc.)
        $null = $FinalColumns.Add($CleanName)
    }
}

# Now add columns for each unique process
foreach ($Identity in $ProcessIdentities.Values) {
    $UniqueName = $Identity.UniqueName
    
    foreach ($Metric in $ProcessMetrics) {
        $null = $FinalColumns.Add("process_${UniqueName}_${Metric}")
    }
}

# Sort columns: timestamp + fixed + sorted process columns
$DynamicColumns = ($FinalColumns | Where-Object { $_ -notin $FixedColumns }) | Sort-Object
$FullSchema = @("timestamp") + $FixedColumns + $DynamicColumns

Write-Host "  Total columns: $($FullSchema.Count)" -ForegroundColor Gray

# --- 3. Build Lookup Tables ---
Write-Host "Step 3/4: Building lookup tables..." -ForegroundColor Cyan

# Create reverse mapping: OriginalName -> IdentityKey lookup
# This helps us quickly find the right unique name when processing each row
$OriginalToIdentityKeys = @{}
foreach ($IdentityKey in $ProcessIdentities.Keys) {
    $Identity = $ProcessIdentities[$IdentityKey]
    $OrigName = $Identity.OriginalName
    
    if (-not $OriginalToIdentityKeys.ContainsKey($OrigName)) {
        $OriginalToIdentityKeys[$OrigName] = @()
    }
    
    $OriginalToIdentityKeys[$OrigName] += $IdentityKey
}

# --- 4. Parallel Processing ---
Write-Host "Step 4/4: Extracting data (parallel processing)..." -ForegroundColor Cyan
$IndexedLines = for ($i=0; $i -lt $Lines.Count; $i++) { 
    [PSCustomObject]@{ Id = $i; Json = $Lines[$i] } 
}

$CsvResults = $IndexedLines | ForEach-Object -Parallel {
    $Data = $_.Json | ConvertFrom-Json
    
    # Build mapping for this row: OriginalName -> UniqueName
    $RowProcessMap = @{}
    
    # First, identify all processes in this row by their command lines
    foreach ($prop in $Data.counters.PSObject.Properties) {
        $CounterName = $prop.Name
        
        # Match: __arcspeed_process_svchost#41__command_line
        if ($CounterName -match '^__\w+_process_(.+?)__command_line$') {
            $ProcessNameWithId = $matches[1]
            $CommandLine = $prop.Value
            
            if ($CommandLine) {
                $IdentityKey = "$ProcessNameWithId|$CommandLine"
                $Identity = ($using:ProcessIdentities)[$IdentityKey]
                
                if ($Identity) {
                    $RowProcessMap[$ProcessNameWithId] = $Identity.UniqueName
                }
            }
        }
    }
    
    # Build the CSV row
    $RowData = @{}
    
    # Extract all counter values
    foreach ($prop in $Data.counters.PSObject.Properties) {
        $CounterName = $prop.Name
        $Value = $prop.Value
        
        # Strip __arcspeed_ prefix
        $CleanName = $CounterName -replace '^__\w+_', ''
        
        # Check if it's a process counter
        if ($CleanName -match '^process_(.+?)__(.+)$') {
            $ProcessNameWithId = $matches[1]
            $Metric = $matches[2]
            
            # Map to unique name
            $UniqueName = $RowProcessMap[$ProcessNameWithId]
            
            if ($UniqueName) {
                $FinalColumnName = "process_${UniqueName}_${Metric}"
                $RowData[$FinalColumnName] = $Value
            }
        } else {
            # Non-process counter
            $RowData[$CleanName] = $Value
        }
    }
    
    # Build CSV line
    $LineValues = [System.Collections.Generic.List[string]]::new()
    
    foreach ($Col in $using:FullSchema) {
        if ($Col -eq "timestamp") {
            $LineValues.Add("`"$($Data.timestamp)`"")
            continue
        }
        
        $Val = $RowData[$Col]
        
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

# --- 5. Save CSV ---
Write-Host "Finalizing: Saving CSV..." -ForegroundColor Cyan
$HeaderRow = ($FullSchema | ForEach-Object { "`"$_`"" }) -join ","
$SortedRows = $CsvResults | Sort-Object Id | ForEach-Object { $_.Row }

[System.IO.File]::WriteAllLines($CsvPath, @($HeaderRow) + $SortedRows)

# --- 6. Save Process Identity Map ---
$IdentityMapPath = $JsonPath -replace "\.json$", "_process_map.txt"
$IdentityLines = New-Object System.Collections.Generic.List[string]

$IdentityLines.Add("Process Identity Map")
$IdentityLines.Add("=" * 80)
$IdentityLines.Add("")
$IdentityLines.Add("This file shows how process instances were mapped to unique column names.")
$IdentityLines.Add("Windows can reuse process IDs, so the same 'svchost#70' might represent")
$IdentityLines.Add("different processes at different times based on their command line.")
$IdentityLines.Add("")
$IdentityLines.Add("=" * 80)
$IdentityLines.Add("")

foreach ($IdentityKey in ($ProcessIdentities.Keys | Sort-Object)) {
    $Identity = $ProcessIdentities[$IdentityKey]
    $IdentityLines.Add("Original Name: $($Identity.OriginalName)")
    $IdentityLines.Add("Unique Name:   $($Identity.UniqueName)")
    $IdentityLines.Add("Command Line:  $($Identity.CommandLine)")
    $IdentityLines.Add("-" * 80)
    $IdentityLines.Add("")
}

[System.IO.File]::WriteAllLines($IdentityMapPath, $IdentityLines.ToArray())

Write-Host "`nDone! CSV created with process identity tracking:" -ForegroundColor Green
Write-Host "  Unique process instances: $($ProcessIdentities.Count)" -ForegroundColor Gray
Write-Host "  Total columns: $($FullSchema.Count)" -ForegroundColor Gray
Write-Host "  CSV file: $CsvPath" -ForegroundColor Cyan
Write-Host "  Process map: $IdentityMapPath" -ForegroundColor Cyan

# Show sample of process mappings
Write-Host "`nSample process mappings (first 5):" -ForegroundColor Yellow
$ProcessIdentities.Values | Select-Object -First 5 | ForEach-Object {
    Write-Host "  $($_.OriginalName) -> $($_.UniqueName)" -ForegroundColor Gray
}) {
                    $BaseName = $matches[1]
                } else {
                    $BaseName = $ProcessNameWithId
                }
                
                # Increment counter for this base name
                if (-not $ProcessCounter.ContainsKey($BaseName)) {
                    $ProcessCounter[$BaseName] = 1
                } else {
                    $ProcessCounter[$BaseName]++
                }
                
                $UniqueId = $ProcessCounter[$BaseName]
                
                $ProcessIdentities[$IdentityKey] = @{
                    OriginalName = $ProcessNameWithId
                    UniqueName = "${BaseName}_${UniqueId}"
                    BaseName = $BaseName
                    CommandLine = $CommandLine
                }
            }
        }
    }
}

Write-Host "  Found $($ProcessIdentities.Count) unique process instances" -ForegroundColor Gray

# --- 2. Build Column Schema ---
Write-Host "Step 2/4: Building column schema..." -ForegroundColor Cyan

# Fixed system counters (after stripping __arcspeed_ prefix)
$FixedColumns = @(
    "memory_pool_nonpaged_allocs", "memory_pool_nonpaged_bytes", "memory_pool_paged_bytes",
    "memory_system_driver_total_bytes", "memory_available_mbytes", "paging_file_total_per_usage",
    "system_context_switches_per_sec", "system_processor_queue_length", "system_system_calls_per_sec",
    "system_system_up_time", "objects_processes", "objects_threads",
    "processor__total__interrupts_sec", "processor__total__percent_dpc_time"
)

# Build set of all unique columns we'll need
$FinalColumns = New-Object 'System.Collections.Generic.HashSet[string]'

# Add fixed columns
foreach ($col in $FixedColumns) {
    $null = $FinalColumns.Add($col)
}

# For each process identity, create columns for all their metrics
$ProcessMetrics = New-Object 'System.Collections.Generic.HashSet[string]'

foreach ($CounterName in $AllCounters) {
    # Strip __arcspeed_ prefix
    $CleanName = $CounterName -replace '^__\w+_', ''
    
    # Check if it's a process counter: process_NAME__metric
    if ($CleanName -match '^process_(.+?)__(.+)$') {
        $ProcessNameWithId = $matches[1]  # e.g., "svchost#41"
        $Metric = $matches[2]              # e.g., "handle_count"
        
        $null = $ProcessMetrics.Add($Metric)
    } else {
        # Non-process counter (system, memory, etc.)
        $null = $FinalColumns.Add($CleanName)
    }
}

# Now add columns for each unique process
foreach ($Identity in $ProcessIdentities.Values) {
    $UniqueName = $Identity.UniqueName
    
    foreach ($Metric in $ProcessMetrics) {
        $null = $FinalColumns.Add("process_${UniqueName}_${Metric}")
    }
}

# Sort columns: timestamp + fixed + sorted process columns
$DynamicColumns = ($FinalColumns | Where-Object { $_ -notin $FixedColumns }) | Sort-Object
$FullSchema = @("timestamp") + $FixedColumns + $DynamicColumns

Write-Host "  Total columns: $($FullSchema.Count)" -ForegroundColor Gray

# --- 3. Build Lookup Tables ---
Write-Host "Step 3/4: Building lookup tables..." -ForegroundColor Cyan

# Create reverse mapping: OriginalName -> IdentityKey lookup
# This helps us quickly find the right unique name when processing each row
$OriginalToIdentityKeys = @{}
foreach ($IdentityKey in $ProcessIdentities.Keys) {
    $Identity = $ProcessIdentities[$IdentityKey]
    $OrigName = $Identity.OriginalName
    
    if (-not $OriginalToIdentityKeys.ContainsKey($OrigName)) {
        $OriginalToIdentityKeys[$OrigName] = @()
    }
    
    $OriginalToIdentityKeys[$OrigName] += $IdentityKey
}

# --- 4. Parallel Processing ---
Write-Host "Step 4/4: Extracting data (parallel processing)..." -ForegroundColor Cyan
$IndexedLines = for ($i=0; $i -lt $Lines.Count; $i++) { 
    [PSCustomObject]@{ Id = $i; Json = $Lines[$i] } 
}

$CsvResults = $IndexedLines | ForEach-Object -Parallel {
    $Data = $_.Json | ConvertFrom-Json
    
    # Build mapping for this row: OriginalName -> UniqueName
    $RowProcessMap = @{}
    
    # First, identify all processes in this row by their command lines
    foreach ($prop in $Data.counters.PSObject.Properties) {
        $CounterName = $prop.Name
        
        # Match: __arcspeed_process_svchost#41__command_line
        if ($CounterName -match '^__\w+_process_(.+?)__command_line$') {
            $ProcessNameWithId = $matches[1]
            $CommandLine = $prop.Value
            
            if ($CommandLine) {
                $IdentityKey = "$ProcessNameWithId|$CommandLine"
                $Identity = ($using:ProcessIdentities)[$IdentityKey]
                
                if ($Identity) {
                    $RowProcessMap[$ProcessNameWithId] = $Identity.UniqueName
                }
            }
        }
    }
    
    # Build the CSV row
    $RowData = @{}
    
    # Extract all counter values
    foreach ($prop in $Data.counters.PSObject.Properties) {
        $CounterName = $prop.Name
        $Value = $prop.Value
        
        # Strip __arcspeed_ prefix
        $CleanName = $CounterName -replace '^__\w+_', ''
        
        # Check if it's a process counter
        if ($CleanName -match '^process_(.+?)__(.+)$') {
            $ProcessNameWithId = $matches[1]
            $Metric = $matches[2]
            
            # Map to unique name
            $UniqueName = $RowProcessMap[$ProcessNameWithId]
            
            if ($UniqueName) {
                $FinalColumnName = "process_${UniqueName}_${Metric}"
                $RowData[$FinalColumnName] = $Value
            }
        } else {
            # Non-process counter
            $RowData[$CleanName] = $Value
        }
    }
    
    # Build CSV line
    $LineValues = [System.Collections.Generic.List[string]]::new()
    
    foreach ($Col in $using:FullSchema) {
        if ($Col -eq "timestamp") {
            $LineValues.Add("`"$($Data.timestamp)`"")
            continue
        }
        
        $Val = $RowData[$Col]
        
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

# --- 5. Save CSV ---
Write-Host "Finalizing: Saving CSV..." -ForegroundColor Cyan
$HeaderRow = ($FullSchema | ForEach-Object { "`"$_`"" }) -join ","
$SortedRows = $CsvResults | Sort-Object Id | ForEach-Object { $_.Row }

[System.IO.File]::WriteAllLines($CsvPath, @($HeaderRow) + $SortedRows)

# --- 6. Save Process Identity Map ---
$IdentityMapPath = $JsonPath -replace "\.json$", "_process_map.txt"
$IdentityLines = New-Object System.Collections.Generic.List[string]

$IdentityLines.Add("Process Identity Map")
$IdentityLines.Add("=" * 80)
$IdentityLines.Add("")
$IdentityLines.Add("This file shows how process instances were mapped to unique column names.")
$IdentityLines.Add("Windows can reuse process IDs, so the same 'svchost#70' might represent")
$IdentityLines.Add("different processes at different times based on their command line.")
$IdentityLines.Add("")
$IdentityLines.Add("=" * 80)
$IdentityLines.Add("")

foreach ($IdentityKey in ($ProcessIdentities.Keys | Sort-Object)) {
    $Identity = $ProcessIdentities[$IdentityKey]
    $IdentityLines.Add("Original Name: $($Identity.OriginalName)")
    $IdentityLines.Add("Unique Name:   $($Identity.UniqueName)")
    $IdentityLines.Add("Command Line:  $($Identity.CommandLine)")
    $IdentityLines.Add("-" * 80)
    $IdentityLines.Add("")
}

[System.IO.File]::WriteAllLines($IdentityMapPath, $IdentityLines.ToArray())

Write-Host "`nDone! CSV created with process identity tracking:" -ForegroundColor Green
Write-Host "  Unique process instances: $($ProcessIdentities.Count)" -ForegroundColor Gray
Write-Host "  Total columns: $($FullSchema.Count)" -ForegroundColor Gray
Write-Host "  CSV file: $CsvPath" -ForegroundColor Cyan
Write-Host "  Process map: $IdentityMapPath" -ForegroundColor Cyan

# Show sample of process mappings
Write-Host "`nSample process mappings (first 5):" -ForegroundColor Yellow
$ProcessIdentities.Values | Select-Object -First 5 | ForEach-Object {
    Write-Host "  $($_.OriginalName) -> $($_.UniqueName)" -ForegroundColor Gray
}