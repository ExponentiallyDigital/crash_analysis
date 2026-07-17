# secure_kernel_monitor.ps1
# Monitor system state to correlate with secure kernel crashes
# Run with elevated privileges

# !!!!!!!!!!!!! 
# !!!!!!!!!!!!! edit below line:
# !!!!!!!!!!!!! 
param(
    [string]$LogDir = "C:\PerfLogs\SecureKernelMonitor",
    [int]$IntervalSeconds = 60
)

# Ensure log directory exists
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir | Out-Null
}

Write-Host "=== SECURE KERNEL CRASH MONITORING ===" -ForegroundColor Cyan
Write-Host "Log Directory: $LogDir" -ForegroundColor Gray
Write-Host "Interval: $IntervalSeconds seconds`n" -ForegroundColor Gray

$StartTime = Get-Date
Write-Host "Monitoring started at $StartTime" -ForegroundColor Green
Write-Host "Press Ctrl+C to stop`n" -ForegroundColor Yellow

$IterationCount = 0

try {
    while ($true) {
        $IterationCount++
        $Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $Uptime = (Get-Date) - $StartTime
        
        Write-Host "[$Timestamp] Iteration $IterationCount (Uptime: $($Uptime.ToString('hh\:mm\:ss')))" -ForegroundColor Cyan
        
        # Create iteration log file
        $LogFile = Join-Path $LogDir "${Timestamp}_system_state.txt"
        
        $Report = @"
================================================================================
SYSTEM STATE SNAPSHOT - $Timestamp
================================================================================
Session Uptime: $($Uptime.ToString('hh\:mm\:ss'))
System Uptime: $((Get-CimInstance Win32_OperatingSystem).LastBootUpTime)

"@

        # 1. Driver Verifier Status
        $Report += "`n=== DRIVER VERIFIER STATUS ===`n"
        try {
            $VerifierOutput = & verifier /query 2>&1 | Out-String
            $Report += $VerifierOutput
        } catch {
            $Report += "Error querying verifier: $($_.Exception.Message)`n"
        }
        
        # 2. Memory Pool Status
        $Report += "`n=== MEMORY POOL STATUS ===`n"
        try {
            $Memory = Get-CimInstance Win32_OperatingSystem
            $Report += "Total Physical Memory: $([math]::Round($Memory.TotalVisibleMemorySize / 1MB, 2)) GB`n"
            $Report += "Free Physical Memory: $([math]::Round($Memory.FreePhysicalMemory / 1MB, 2)) GB`n"
            $Report += "Total Virtual Memory: $([math]::Round($Memory.TotalVirtualMemorySize / 1MB, 2)) GB`n"
            $Report += "Free Virtual Memory: $([math]::Round($Memory.FreeVirtualMemory / 1MB, 2)) GB`n"
            
            # Pool counters
            $PoolPaged = (Get-Counter '\Memory\Pool Paged Bytes' -SampleInterval 1 -MaxSamples 1).CounterSamples.CookedValue
            $PoolNonpaged = (Get-Counter '\Memory\Pool Nonpaged Bytes' -SampleInterval 1 -MaxSamples 1).CounterSamples.CookedValue
            $Report += "Pool Paged: $([math]::Round($PoolPaged / 1MB, 2)) MB`n"
            $Report += "Pool Nonpaged: $([math]::Round($PoolNonpaged / 1MB, 2)) MB`n"
        } catch {
            $Report += "Error getting memory info: $($_.Exception.Message)`n"
        }
        
        # 3. Loaded Verified Drivers
        $Report += "`n=== VERIFIED DRIVERS (Currently Loaded) ===`n"
        try {
            $VerifiedDrivers = @(
                'adgnetworkwfpdrv.sys', 'amd3dvcache.sys', 'amdappcompat.sys',
                'amdgpio2.sys', 'amdgpio3.sys', 'amdi2c.sys', 'amdppkg.sys',
                'amdpsp.sys', 'e2fn.sys', 'farflt11.sys', 'logi_joy_bus_enum.sys',
                'logi_joy_vir_hid.sys', 'logi_joy_xlcore.sys', 'logi_lamparray.sys',
                'mbae.sys', 'mbam.sys', 'mbamchameleon.sys', 'mbamswissarmy.sys',
                'mwac.sys', 'nvlddmkm.sys', 'rtu56cx22x64.sys', 'rtusba64.sys'
            )
            
            $LoadedDrivers = Get-CimInstance Win32_SystemDriver | 
                Where-Object { $_.PathName -match '\.sys$' } |
                Select-Object Name, State, PathName
            
            foreach ($VerDriver in $VerifiedDrivers) {
                $Driver = $LoadedDrivers | Where-Object { $_.PathName -match [regex]::Escape($VerDriver) }
                if ($Driver) {
                    $Report += "  [LOADED] $VerDriver - State: $($Driver.State)`n"
                } else {
                    $Report += "  [NOT LOADED] $VerDriver`n"
                }
            }
        } catch {
            $Report += "Error checking drivers: $($_.Exception.Message)`n"
        }
        
        # 4. Recent System Events (Errors/Warnings)
        $Report += "`n=== RECENT SYSTEM EVENTS (Last $IntervalSeconds seconds) ===`n"
        try {
            $RecentEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'System'
                Level = 1,2,3  # Critical, Error, Warning
                StartTime = (Get-Date).AddSeconds(-$IntervalSeconds)
            } -MaxEvents 20 -ErrorAction SilentlyContinue
            
            if ($RecentEvents) {
                foreach ($Event in $RecentEvents) {
                    $Report += "[$($Event.TimeCreated)] [$($Event.LevelDisplayName)] $($Event.ProviderName): $($Event.Message -replace "`n",' ')`n"
                }
            } else {
                $Report += "No critical/error/warning events in last $IntervalSeconds seconds`n"
            }
        } catch {
            $Report += "Error getting events: $($_.Exception.Message)`n"
        }
        
        # 5. Verifier Violation Events
        $Report += "`n=== DRIVER VERIFIER VIOLATIONS ===`n"
        try {
            $VerifierEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'System'
                ProviderName = 'Microsoft-Windows-Kernel-Verifier'
                StartTime = (Get-Date).AddSeconds(-$IntervalSeconds)
            } -MaxEvents 10 -ErrorAction SilentlyContinue
            
            if ($VerifierEvents) {
                foreach ($Event in $VerifierEvents) {
                    $Report += "[$($Event.TimeCreated)] ID:$($Event.Id) - $($Event.Message)`n"
                }
            } else {
                $Report += "No verifier violations in last $IntervalSeconds seconds`n"
            }
        } catch {
            $Report += "No verifier events found`n"
        }
        
        # 6. GPU/Display Driver Status (NVIDIA specific)
        $Report += "`n=== GPU DRIVER STATUS ===`n"
        try {
            $GPU = Get-CimInstance Win32_VideoController | Select-Object -First 1
            if ($GPU) {
                $Report += "Name: $($GPU.Name)`n"
                $Report += "Driver Version: $($GPU.DriverVersion)`n"
                $Report += "Driver Date: $($GPU.DriverDate)`n"
                $Report += "Status: $($GPU.Status)`n"
            }
        } catch {
            $Report += "Error getting GPU info: $($_.Exception.Message)`n"
        }
        
        # 7. Handle Count (potential resource leak indicator)
        $Report += "`n=== TOP PROCESSES BY HANDLE COUNT ===`n"
        try {
            $TopHandles = Get-Process | 
                Sort-Object HandleCount -Descending | 
                Select-Object -First 10 Name, HandleCount, WorkingSet
            
            foreach ($Proc in $TopHandles) {
                $Report += "$($Proc.Name): $($Proc.HandleCount) handles, $([math]::Round($Proc.WorkingSet/1MB,2)) MB`n"
            }
        } catch {
            $Report += "Error getting process info: $($_.Exception.Message)`n"
        }
        
        $Report += "`n================================================================================"
        
        # Save to file
        $Report | Out-File -FilePath $LogFile -Encoding UTF8
        Write-Host "  Saved: $LogFile" -ForegroundColor Gray
        
        # Wait for next iteration
        Start-Sleep -Seconds $IntervalSeconds
    }
}
catch {
    $ErrorTime = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $ErrorLog = Join-Path $LogDir "${ErrorTime}_monitor_error.txt"
    "Monitor Error: $($_.Exception.Message)" | Out-File -FilePath $ErrorLog
    Write-Host "`nMonitoring stopped due to error. See: $ErrorLog" -ForegroundColor Red
}
finally {
    Write-Host "`nMonitoring stopped at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
    Write-Host "Total runtime: $($Uptime.ToString('hh\:mm\:ss'))" -ForegroundColor Gray
}