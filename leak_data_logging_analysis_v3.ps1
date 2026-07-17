# leak_data_logging_analysis_v3.ps1
# Enhanced performance counter analysis for detecting leaks and system issues

# !!!!!!!!!!!!! 
# !!!!!!!!!!!!! edit below line:
# !!!!!!!!!!!!! 
$CsvPath = "c:\perflogs\2026-01-15_05-11-40_Process_data_log.csv"

$csv = Import-Csv $CsvPath

$boot = $csv[0]
$crash = $csv[-1]
$uptime = [TimeSpan]::FromSeconds($crash.system_system_up_time)
$loggingDuration = [TimeSpan]::FromSeconds([int]$crash.system_system_up_time - [int]$boot.system_system_up_time)

# Calculate memory leak
$memLost = [int]$boot.memory_available_mbytes - [int]$crash.memory_available_mbytes
$leakRate = [math]::Round($memLost / $uptime.TotalHours, 2)

$summary = @"
=== SYSTEM OVERVIEW ===
"@
$overviewTable = @(
    [PSCustomObject]@{ Metric = "Uptime (when logging ended)"; Value = $uptime.ToString("hh\:mm\:ss") }
    [PSCustomObject]@{ Metric = "Data logging active for"; Value = $loggingDuration.ToString("hh\:mm\:ss") }
    [PSCustomObject]@{ Metric = "Start available memory"; Value = "$($boot.memory_available_mbytes) MB" }
    [PSCustomObject]@{ Metric = "End available memory"; Value = "$($crash.memory_available_mbytes) MB" }
    [PSCustomObject]@{ Metric = "Memory Lost"; Value = "$memLost MB" }
    [PSCustomObject]@{ Metric = "Consumption/leak rate"; Value = "$leakRate MB/hour" }
) | Format-Table -AutoSize | Out-String
$summary += "`n$overviewTable"

# === POOL ANALYSIS (Enhanced) ===
$summary += "`n=== POOL ANALYSIS ===`n"
$npPoolGrowth = ($crash.memory_pool_nonpaged_bytes - $boot.memory_pool_nonpaged_bytes)
$pPoolGrowth = ($crash.memory_pool_paged_bytes - $boot.memory_pool_paged_bytes)

$poolTable = @(
    [PSCustomObject]@{ 
        Pool = "NonPaged"
        StartMB = [math]::Round($boot.memory_pool_nonpaged_bytes/1MB, 2)
        EndMB = [math]::Round($crash.memory_pool_nonpaged_bytes/1MB, 2)
        GrowthMB = [math]::Round($npPoolGrowth/1MB, 2)
        "Growth/hr" = [math]::Round(($npPoolGrowth/1MB) / $loggingDuration.TotalHours, 2)
    }
    [PSCustomObject]@{ 
        Pool = "Paged"
        StartMB = [math]::Round($boot.memory_pool_paged_bytes/1MB, 2)
        EndMB = [math]::Round($crash.memory_pool_paged_bytes/1MB, 2)
        GrowthMB = [math]::Round($pPoolGrowth/1MB, 2)
        "Growth/hr" = [math]::Round(($pPoolGrowth/1MB) / $loggingDuration.TotalHours, 2)
    }
) | Format-Table -AutoSize | Out-String
$summary += $poolTable

# Check for fragmentation leak
if ($boot.PSObject.Properties.Name -contains "memory_pool_nonpaged_allocs") {
    $allocGrowth = [long]$crash.memory_pool_nonpaged_allocs - [long]$boot.memory_pool_nonpaged_allocs
    $bytesPerAlloc = if ($allocGrowth -gt 0) { [math]::Round($npPoolGrowth / $allocGrowth, 2) } else { 0 }
    
    if ($allocGrowth -gt 1000 -and $bytesPerAlloc -lt 100) {
        $summary += "[WARNING] Fragmentation leak detected! $allocGrowth new allocations averaging only $bytesPerAlloc bytes each.`n"
        $summary += "   This indicates a driver (likely network/storage) is making thousands of tiny allocations.`n`n"
    }
}

# === SYSTEM STABILITY METRICS ===
$summary += "`n=== SYSTEM STABILITY METRICS ===`n"

$stabilityMetrics = @()

# Context Switches
if ($boot.PSObject.Properties.Name -contains "system_context_switches_per_sec") {
    $csStart = [long]$boot.system_context_switches_per_sec
    $csEnd = [long]$crash.system_context_switches_per_sec
    $csStatus = if ($csEnd -gt 1000000) { "[CRITICAL]" } elseif ($csEnd -gt 500000) { "[High]" } else { "OK" }
    $stabilityMetrics += [PSCustomObject]@{
        Metric = "Context Switches/sec"
        Start = "{0:N0}" -f $csStart
        End = "{0:N0}" -f $csEnd
        Status = $csStatus
    }
}

# Interrupts
if ($boot.PSObject.Properties.Name -contains "processor_total_interrupts_per_sec") {
    $intStart = [long]$boot.processor_total_interrupts_per_sec
    $intEnd = [long]$crash.processor_total_interrupts_per_sec
    $intStatus = if ($intEnd -gt 50000) { "[High - check hardware/drivers]" } else { "OK" }
    $stabilityMetrics += [PSCustomObject]@{
        Metric = "Interrupts/sec"
        Start = "{0:N0}" -f $intStart
        End = "{0:N0}" -f $intEnd
        Status = $intStatus
    }
}

# DPC Time
if ($boot.PSObject.Properties.Name -contains "processor_total_percent_dpc_time") {
    $dpcStart = [double]$boot.processor_total_percent_dpc_time
    $dpcEnd = [double]$crash.processor_total_percent_dpc_time
    $dpcStatus = if ($dpcEnd -gt 10) { "[CRITICAL - driver issue]" } elseif ($dpcEnd -gt 5) { "[High]" } else { "OK" }
    $stabilityMetrics += [PSCustomObject]@{
        Metric = "% DPC Time"
        Start = "$dpcStart%"
        End = "$dpcEnd%"
        Status = $dpcStatus
    }
}

# System Calls
if ($boot.PSObject.Properties.Name -contains "system_system_calls_per_sec") {
    $scStart = [long]$boot.system_system_calls_per_sec
    $scEnd = [long]$crash.system_system_calls_per_sec
    $stabilityMetrics += [PSCustomObject]@{
        Metric = "System Calls/sec"
        Start = "{0:N0}" -f $scStart
        End = "{0:N0}" -f $scEnd
        Status = "Monitor for spikes"
    }
}

if ($stabilityMetrics.Count -gt 0) {
    $summary += ($stabilityMetrics | Format-Table -AutoSize | Out-String)
} else {
    $summary += "System stability counters not found in CSV.`n"
}

# === TOP HANDLE CONSUMERS ===

if ($stabilityMetrics.Count -gt 0) {
    $summary += ($stabilityMetrics | Format-Table -AutoSize | Out-String)
} else {
    $summary += "System stability counters not found in CSV.`n"
}

# === TOP HANDLE CONSUMERS ===
$handleCols = $csv[0].PSObject.Properties.Name | Where-Object {$_ -like "process_*_handle_count"}
$handles = @{}
foreach ($col in $handleCols) {
    $value = $crash.$col
    if ($value -and $value -ne "" -and [int]$value -gt 0) {
        $procName = $col -replace 'process_(.+)_handle_count', '$1'
        $handles[$procName] = [int]$value
    }
}

$top10 = $handles.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10
$summary += "`n=== TOP PROCESSES BY HANDLE COUNT ===`n"
$top10Table = $top10 | ForEach-Object {
    $procName = $_.Key
    $bootCol = "process_$($procName)_handle_count"
    $bootVal = if ($boot.$bootCol) { [int]$boot.$bootCol } else { 0 }
    $growth = $_.Value - $bootVal
    $growthRate = [math]::Round($growth / $loggingDuration.TotalHours, 1)
    $status = if ($_.Value -gt 10000) { "[LEAK!]" } elseif ($growthRate -gt 100) { "[Growing]" } else { "" }
    
    [PSCustomObject]@{
        Process = $procName
        Handles = $_.Value
        Growth = "+$growth"
        "Growth/hr" = "$growthRate/hr"
        Status = $status
    }
} | Format-Table -AutoSize | Out-String
$summary += $top10Table

# === COMPREHENSIVE PROCESS ANALYSIS ===
$summary += "`n=== PROCESS LEAK DETECTION ===`n"

$suspects = @()
$allProcesses = @{}

# Get all unique process names (excluding "total")
$handleCols | ForEach-Object {
    $procName = $_ -replace 'process_(.+)_handle_count', '$1'
    if ($procName -ne "total" -and $procName -notin $allProcesses.Keys) {
        $allProcesses[$procName] = @{}
    }
}

foreach ($procName in $allProcesses.Keys) {
    $hCol = "process_$($procName)_handle_count"
    $tCol = "process_$($procName)_thread_count"
    $wsCol = "process_$($procName)_working_set"
    $pbCol = "process_$($procName)_private_bytes"
    $vbCol = "process_$($procName)_virtual_bytes"
    $pnpbCol = "process_$($procName)_pool_nonpaged_bytes"
    $cpuCol = "process_$($procName)__processor_time"
    
    # Get values
    $hBoot = if ($boot.$hCol) { [int]$boot.$hCol } else { 0 }
    $hCrash = if ($crash.$hCol) { [int]$crash.$hCol } else { 0 }
    $hGrowth = $hCrash - $hBoot
    
    $tBoot = if ($boot.$tCol) { [int]$boot.$tCol } else { 0 }
    $tCrash = if ($crash.$tCol) { [int]$crash.$tCol } else { 0 }
    $tGrowth = $tCrash - $tBoot
    
    $wsBoot = if ($boot.$wsCol) { [long]$boot.$wsCol } else { 0 }
    $wsCrash = if ($crash.$wsCol) { [long]$crash.$wsCol } else { 0 }
    $wsGrowthMB = [math]::Round(($wsCrash - $wsBoot) / 1MB, 0)
    
    $pbBoot = if ($boot.$pbCol) { [long]$boot.$pbCol } else { 0 }
    $pbCrash = if ($crash.$pbCol) { [long]$crash.$pbCol } else { 0 }
    $pbGrowthMB = [math]::Round(($pbCrash - $pbBoot) / 1MB, 0)
    
    $vbBoot = if ($boot.$vbCol) { [long]$boot.$vbCol } else { 0 }
    $vbCrash = if ($crash.$vbCol) { [long]$crash.$vbCol } else { 0 }
    $vbGrowthMB = [math]::Round(($vbCrash - $vbBoot) / 1MB, 0)
    $vbCrashMB = [math]::Round($vbCrash / 1MB, 0)
    $wsCrashMB = [math]::Round($wsCrash / 1MB, 0)
    
    $pnpbBoot = if ($boot.$pnpbCol) { [long]$boot.$pnpbCol } else { 0 }
    $pnpbCrash = if ($crash.$pnpbCol) { [long]$crash.$pnpbCol } else { 0 }
    $pnpbGrowthKB = [math]::Round(($pnpbCrash - $pnpbBoot) / 1KB, 0)
    
    $cpuCrash = if ($crash.$cpuCol) { [double]$crash.$cpuCol } else { 0 }
    
    # Detection logic
    $issues = @()
    
    # Handle leak detection
    if ($hCrash -gt 10000) {
        $issues += "HANDLE_LEAK(>10k)"
    } elseif ($hGrowth -gt 500 -and $hCrash -gt 1000) {
        $issues += "Handle_Growth"
    }
    
    # Private bytes leak (memory leak)
    if ($pbGrowthMB -gt 50) {
        $issues += "MEMORY_LEAK"
    }
    
    # Virtual address space leak - only flag if GROWING significantly (>100MB growth)
    # Static large virtual bytes are normal for modern processes
    if ($vbGrowthMB -gt 100) {
        $issues += "VIRTUAL_LEAK"
    }
    
    # Thread bloat
    if ($tCrash -gt 100) {
        $issues += "THREAD_BLOAT"
    } elseif ($tGrowth -gt 20) {
        $issues += "Thread_Growth"
    }
    
    # Pool nonpaged leak
    if ($pnpbGrowthKB -gt 1000) {
        $issues += "POOL_NP_LEAK"
    }
    
    # Zombie thread (high CPU, no useful work)
    if ($cpuCrash -gt 50 -and $tCrash -gt 10) {
        $issues += "HIGH_CPU"
    }
    
    # Add to suspects if any issues found
    if ($issues.Count -gt 0) {
        $suspects += [PSCustomObject]@{
            Process = $procName
            Issues = $issues -join ", "
            Handles = "$hCrash (+$hGrowth)"
            Threads = "$tCrash (+$tGrowth)"
            "PrivateMB" = "$([math]::Round($pbCrash/1MB, 0)) (+$pbGrowthMB)"
            "VirtualMB" = "$vbCrashMB (+$vbGrowthMB)"
            "PoolNP_KB" = "$([math]::Round($pnpbCrash/1KB, 0)) (+$pnpbGrowthKB)"
            "CPU%" = $cpuCrash
        }
    }
}

if ($suspects.Count -eq 0) {
    $summary += "[OK] No processes detected with anomalies.`n"
} else {
    $suspectsTable = $suspects | Sort-Object {$_.Issues -like "*LEAK*"} -Descending | Format-Table -AutoSize -Wrap | Out-String
    $summary += $suspectsTable
    
    $summary += "`nLegend:`n"
    $summary += "  HANDLE_LEAK    = Greater than 10,000 handles`n"
    $summary += "  MEMORY_LEAK    = Private Bytes grew more than 50MB`n"
    $summary += "  VIRTUAL_LEAK   = Virtual Bytes grew more than 100MB (address space leak)`n"
    $summary += "  THREAD_BLOAT   = More than 100 threads`n"
    $summary += "  POOL_NP_LEAK   = Pool Nonpaged Bytes grew more than 1MB`n"
    $summary += "  HIGH_CPU       = More than 50% CPU usage`n`n"
}

# === DRIVER LEAK DETECTION ===
$summary += "`n=== DRIVER LEAK ANALYSIS ===`n"

# Nonpaged pool growth indicates driver leaks
$npGrowthMB = [math]::Round($npPoolGrowth / 1MB, 2)
if ($npGrowthMB -gt 10) {
    $summary += "[WARNING] System NonPaged Pool grew by $npGrowthMB MB`n"
    $summary += "   This typically indicates a kernel driver leak (storage, network, or graphics driver).`n"
    $summary += "   Common culprits: Nvidia, AMD, network adapters, antivirus, VPN software.`n`n"
    
    # Show processes with Pool Nonpaged growth
    $pnpLeakers = $suspects | Where-Object { $_.Issues -like "*POOL_NP*" }
    if ($pnpLeakers) {
        $summary += "   Processes contributing to Pool NonPaged growth:`n"
        $pnpLeakers | ForEach-Object { $summary += "     - $($_.Process): $($_.PoolNP_KB)`n" }
        $summary += "`n"
    }
} else {
    $summary += "[OK] NonPaged Pool growth is normal ($npGrowthMB MB).`n`n"
}

# === SVCHOST ANALYSIS ===
$summary += "`n=== SVCHOST INSTANCES ANALYSIS ===`n"

# Find all svchost columns dynamically
$svchostHandleCols = $csv[0].PSObject.Properties.Name | Where-Object {
    $_ -like "process_svchost*_handle_count"
}

if ($svchostHandleCols.Count -eq 0) {
    $summary += "No svchost instances found in CSV.`n"
} else {
    $svchostData = $svchostHandleCols | ForEach-Object {
        $hcCol = $_
        $procName = $hcCol -replace 'process_(.+)_handle_count', '$1'
        
        $wsCol = "process_$($procName)_working_set"
        $pbCol = "process_$($procName)_private_bytes"
        $tCol = "process_$($procName)_thread_count"
        $cmdlineCol = "process_$($procName)_command_line"
        
        $hcBoot = if ($boot.$hcCol) { [int]$boot.$hcCol } else { 0 }
        $hcCrash = if ($crash.$hcCol) { [int]$crash.$hcCol } else { 0 }
        $growth = $hcCrash - $hcBoot
        
        $tBoot = if ($boot.$tCol) { [int]$boot.$tCol } else { 0 }
        $tCrash = if ($crash.$tCol) { [int]$crash.$tCol } else { 0 }
        
        $pbBoot = if ($boot.$pbCol) { [long]$boot.$pbCol } else { 0 }
        $pbCrash = if ($crash.$pbCol) { [long]$crash.$pbCol } else { 0 }
        $pbGrowthMB = [math]::Round(($pbCrash - $pbBoot) / 1MB, 0)
        
        if ($hcCrash -gt 0) {
            $cmdline = if ($crash.$cmdlineCol) { $crash.$cmdlineCol } else { "" }
            $cmdline = $cmdline -replace '^C:\\WINDOWS\\system32\\', ''
            $cmdline = $cmdline -replace '^C:\\Windows\\System32\\', ''
            
            # Extract service name from command line if possible
            if ($cmdline -match '-k\s+(\S+)') {
                $serviceName = $matches[1]
            } elseif ($cmdline -match '-s\s+(\S+)') {
                $serviceName = $matches[1]
            } else {
                $serviceName = ""
            }
            
            [PSCustomObject]@{
                Instance = $procName
                Service = $serviceName
                Handles = $hcCrash
                HandleGrowth = $growth
                "Growth/hr" = [math]::Round($growth / $loggingDuration.TotalHours, 1)
                Threads = $tCrash
                "PrivateMB" = [math]::Round($pbCrash/1MB, 0)
                "Priv.Growth" = $pbGrowthMB
                "CommandLine" = if ($cmdline.Length -gt 60) { $cmdline.Substring(0, 57) + "..." } else { $cmdline }
            }
        }
    } | Where-Object { $_ -ne $null } | Sort-Object Handles -Descending | Select-Object -First 20
    
    if ($svchostData) {
        $svchostTable = $svchostData | Format-Table -AutoSize -Wrap | Out-String
        $summary += $svchostTable
        
        # Highlight any svchost with significant handle or memory growth
        $leakySvchosts = $svchostData | Where-Object { 
            $_."Growth/hr" -gt 50 -or $_."Priv.Growth" -gt 10 
        }
        if ($leakySvchosts) {
            $summary += "`nSvchost instances with notable growth:`n"
            $leakySvchosts | ForEach-Object {
                $summary += "  - $($_.Instance) [$($_.Service)]: +$($_.HandleGrowth) handles, +$($_.'Priv.Growth')MB memory`n"
            }
            $summary += "`n"
        }
    } else {
        $summary += "No active svchost instances found.`n"
    }
}

# === RECOMMENDATIONS ===
$summary += "`n=== RECOMMENDATIONS ===`n"

$recommendations = @()

if ($npGrowthMB -gt 10) {
    $recommendations += "1. Update or reinstall graphics, storage, and network drivers"
}

if ($suspects | Where-Object { $_.Issues -like "*HANDLE_LEAK*" }) {
    $recommendations += "2. Restart processes with handle leaks or update the software"
}

if ($suspects | Where-Object { $_.Issues -like "*MEMORY_LEAK*" }) {
    $recommendations += "3. Memory leaking processes should be restarted or updated"
}

if ($crash.PSObject.Properties.Name -contains "processor__total__dpc_time") {
    if ([double]$crash.processor__total__dpc_time -gt 5) {
        $recommendations += "4. High DPC time detected - check for problematic drivers using 'latencymon' tool"
    }
}

if ($recommendations.Count -eq 0) {
    $summary += "[OK] System appears healthy based on available metrics.`n"
} else {
    $recommendations | ForEach-Object { $summary += "$_`n" }
}

$summary | Write-Host

$BaseName = [System.IO.Path]::GetFileNameWithoutExtension($CsvPath)
$OutputTxt = "C:\perflogs\$($BaseName)_summary.txt"
$summary | Out-File $OutputTxt
Write-Host "`nReport saved to: $OutputTxt" -ForegroundColor Green