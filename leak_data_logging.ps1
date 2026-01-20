# leak_data_logging_v3.ps1
# purpose: capture data for memory leak analysis
# Immediate sample then every 30 seconds, writes NDJSON samples with enriched process info (PID + command line)
#
# Updates: includes additional counters for later analysis
# TO do: start and end pof pathys have \\\ eg

$EnableDebug = $false          # set to $true to enable debug logging
$outDir = "C:\PerfLogs"
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$filePath = Join-Path $outDir "$timestamp`_perfdata_log.json"

$intervalSec = 30   # sample every x seconds, set to 30 for prod use, don't use < 10s as it takes time to process the data!
$durationHours = $null
$endTime = if ($durationHours) { (Get-Date).AddHours($durationHours) } else { $null }

$Counters = @(
    "\Memory\Pool Nonpaged Allocs",
    "\Memory\Pool Nonpaged Bytes",
    "\Memory\Pool Paged Bytes",
    "\Memory\System Driver Total Bytes",
    "\Memory\Available MBytes",
    "\Paging File(_Total)\% Usage",
    "\System\Context Switches/sec",
    "\System\Processor Queue Length",
    "\System\System Calls/sec",
    "\System\System Up Time",
    "\Objects\Processes",
    "\Objects\Threads",
    "\Processor(_Total)\Interrupts/sec",
    "\Processor(_Total)\% DPC Time",
    "\Processor(_Total)\% Idle Time",
    "\Processor(_Total)\Interrupts/sec",
    "\PhysicalDisk(_Total)\Avg. Disk sec/Transfer",
    "\PhysicalDisk(_Total)\Disk Transfers/sec",
    "\Process(*)\% Processor Time",
    "\Process(*)\Handle Count",
    "\Process(*)\Pool Nonpaged Bytes",
    "\Process(*)\Private Bytes",
    "\Process(*)\Thread Count",
    "\Process(*)\Virtual Bytes",
    "\Process(*)\Working Set",
    "\Process(*)\ID Process"
)

# Logging helper
function Write-DebugLog {
    param([string]$msg)
    if (-not $EnableDebug) { return }   # only write when debug enabled
    $logFile = Join-Path $outDir "$timestamp`_perfdata_log_err.log"
    "[{0}] {1}" -f (Get-Date).ToString("o"), $msg | Add-Content -Path $logFile
}
# --------------------------------------------------------------------
# Convert-CounterToSampleObject
#   - PID extraction from __id_process counters
#   - WMI lookup for CommandLine + ExecutablePath
#   - Double-escaped command line (B1-B)
#   - Flattened keys injected into sampleObj.counters
# --------------------------------------------------------------------
function Convert-CounterToSampleObject {
    param($counterSampleObject)

    $ts = (Get-Date -Date $counterSampleObject.Timestamp -Format o)

    $sampleObj = @{
        timestamp = $ts
        counters  = @{}
#        processes = @()   # unused but preserved for compatibility
    }

    # Temporary store for process metrics
    $processData = @{}   # keyed by instance name (e.g. "svchost#10")

    # -----------------------------
    # 1. Parse all counters normally
    # -----------------------------
    foreach ($cs in $counterSampleObject.CounterSamples) {

        $inst = if ($cs.InstanceName) { $cs.InstanceName } else { "<Total>" }
        $path = $cs.Path
        $value = $cs.CookedValue

        if ($path -like "\Process(*)\*") {
            # Process-specific counter
            $counterName = ($path -split "\\")[-1] -replace " ", "_"

            if (-not $processData.ContainsKey($inst)) {
                $processData[$inst] = @{ name = $inst }
            }
            $processData[$inst][$counterName] = $value
        }
        else {
            # Global counter
            $key = $path -replace "\\", "_" `
                         -replace "\(", "_" `
                         -replace "\)", "_" `
                         -replace "%", "Percent" `
                         -replace "/", "_per_" `
                         -replace " ", "_"

            $sampleObj.counters[$key] = $value
        }
    }

    # ----------------------------------------------
    # 2. Extract PIDs from flattened id_process keys
    # ----------------------------------------------
    $pidMap = @{}   # processName -> PID
    
    foreach ($key in $sampleObj.counters.Keys) {
        if ($key -match '__arcspeed_process_(.+?)__id_process$') {
            $procName = $matches[1]
            $pidValue = $sampleObj.counters[$key]
            
            if ([int]::TryParse($pidValue.ToString(), [ref]([int]$null))) {
                $pidMap[$procName] = [int]$pidValue
            }
            else {
                Write-DebugLog "WARNING: Failed to parse PID for process '$procName' counter '$key' value '$pidValue'"
            }
        }
    }
    
    if ($pidMap.Count -eq 0) {
        $keysSample = ($sampleObj.counters.Keys | Select-Object -First 5) -join ", "
        $err = "ERROR: No PIDs extracted from id_process counters. Available keys sample: $keysSample"
        Write-Warning $err
        Write-DebugLog $err
    }
    else {
        $pidSummary = $pidMap.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }
        Write-DebugLog ("Extracted PIDs: " + ($pidSummary -join ", "))
    }

    # ----------------------------------------------
    # 3. WMI lookup for each PID
    # ----------------------------------------------
    foreach ($procName in $pidMap.Keys) {
        $procId = $pidMap[$procName]
        $wmi = $null
        
        try {
            $wmi = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $procId" -ErrorAction Stop
        }
        catch {
            $msg = "WMI lookup failed for PID $procId ($procName): $($_.Exception.Message)"
            Write-Warning $msg
            Write-DebugLog $msg
        }
        
        $cmd = $null
        $exe = $null
        
        if ($wmi) {
            $cmd = $wmi.CommandLine
            $exe = $wmi.ExecutablePath
        }
        else {
            Write-DebugLog "No WMI data for PID $procId ($procName)"
        }
        
        # Double-escape command line
        if ($cmd) {
            $cmd = $cmd -replace '"', '\"'
        }
        
        # ----------------------------------------------
        # 4. Inject flattened keys
        # ----------------------------------------------
        $prefix = "__arcspeed_process_{0}__" -f ($procName -replace " ", "_")
        
        # Only add command_line and executable if not already present
        if (-not $sampleObj.counters.ContainsKey("${prefix}command_line")) {
            if ($cmd) {
                $sampleObj.counters["${prefix}command_line"] = $cmd
            }
            else {
                $sampleObj.counters["${prefix}command_line"] = "<unavailable>"
            }
        }
        
        if (-not $sampleObj.counters.ContainsKey("${prefix}executable")) {
            if ($exe) {
                $sampleObj.counters["${prefix}executable"] = $exe
            }
        }
    }

    # ----------------------------------------------
    # 5. Add all process metrics to counters
    # ----------------------------------------------
    foreach ($inst in $processData.Keys) {
        foreach ($k in $processData[$inst].Keys) {
            if ($k -eq "name") { continue }

            $prefix = "__arcspeed_process_{0}__" -f ($inst -replace " ", "_")
            $sampleObj.counters["${prefix}${k}"] = $processData[$inst][$k]
        }
    }

    return $sampleObj
}
Write-Host "Starting sampler. Output file: $filePath" -ForegroundColor Cyan
Write-Host "Immediate sample now, then every $intervalSec seconds." -ForegroundColor Yellow

# ------------------------------------------------------------
# IMMEDIATE SAMPLE
# ------------------------------------------------------------
try {
    $sample = Get-Counter -Counter $Counters -ErrorAction Stop
    $sampleObj = Convert-CounterToSampleObject -counterSampleObject $sample

    # Write first line (overwrite)
    $sampleObj | ConvertTo-Json -Compress | Out-File -FilePath $filePath -Encoding utf8

    Write-DebugLog "Immediate sample captured successfully."
}
catch {
    Write-Warning "Initial Get-Counter failed: $($_.Exception.Message)"
    Write-DebugLog "ERROR: Initial Get-Counter failed on counters: $($Counters -join ', ') Exception: $($_.Exception.Message)"
}

# ------------------------------------------------------------
# SAMPLING LOOP
# ------------------------------------------------------------
while ($true) {

    if ($endTime -and (Get-Date) -ge $endTime) {
        Write-Host "Reached end time. Exiting." -ForegroundColor Green
        Write-DebugLog "Reached end time. Exiting sampler loop."
        break
    }

    Write-Host "Captured sample at $(Get-Date -Format HH:mm:ss)"
    Start-Sleep -Seconds $intervalSec

    try {
        $sample = Get-Counter -Counter $Counters -ErrorAction Stop
        $sampleObj = Convert-CounterToSampleObject -counterSampleObject $sample

        # Append NDJSON
        $sampleObj | ConvertTo-Json -Compress | Add-Content -Path $filePath -Encoding utf8

        Write-DebugLog "Sample appended successfully."
    }
    catch {
        $errFile = Join-Path $outDir "$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')_perfdata_log_err.log"
        $msg = "[$(Get-Date -Format o)] Get-Counter failed on counters: $($Counters -join ', ') Exception: $($_.Exception.Message)"
        $msg | Out-File -FilePath $errFile -Encoding utf8

        Write-Warning $msg
        Write-DebugLog "ERROR: Get-Counter failed during loop: $($_.Exception.Message)"
    }
}
# ------------------------------------------------------------
# END OF SCRIPT
# ------------------------------------------------------------