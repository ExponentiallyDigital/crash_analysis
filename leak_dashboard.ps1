# Real-time leak detection dashboard
#

while ($true) {
    Clear-Host
    Write-Host "=== LEAK DETECTION DASHBOARD ===" -ForegroundColor Cyan
    Write-Host "Time: $(Get-Date)" -ForegroundColor Yellow

    # Top processes by working set
    Write-Host "`nTOP HANDLE USERS:" -ForegroundColor Green
    $top = Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 30

    $table = $top | ForEach-Object {
        $proc = $_
        $procId = $proc.Id

        # Query WMI *per process* (no caching)
        $wmi = Get-WmiObject Win32_Process -Filter "ProcessId=$procId" -ErrorAction SilentlyContinue

        $cmd = ""
        if ($wmi -and $wmi.CommandLine) {
            $cmd = $wmi.CommandLine
            if ($cmd.Length -gt 80) { $cmd = $cmd.Substring(0,80) + "..." }
        }

        [PSCustomObject]@{
            Name          = $proc.Name
            Id            = $procId
            HandleCount   = $proc.HandleCount
            WorkingSetMB  = [math]::Round($proc.WorkingSet64/1MB,2)
            PrivateMB     = [math]::Round($proc.PrivateMemorySize64/1MB,2)
            Cmd           = $cmd
        }
    }

    $table | Format-Table -AutoSize

    # System memory
    Write-Host "`nSYSTEM MEMORY:" -ForegroundColor Green
    $os = Get-CimInstance Win32_OperatingSystem
    $totalMemGB = [math]::Round(($os.TotalVisibleMemorySize / 1MB), 2)
    $freeMemGB  = [math]::Round(($os.FreePhysicalMemory / 1MB), 2)
    $usedMemGB  = $totalMemGB - $freeMemGB
    Write-Host "Total: $totalMemGB GB | Used: $usedMemGB GB | Free: $freeMemGB GB"

    # Total handles
    $totalHandles = (Get-Process | Measure-Object HandleCount -Sum).Sum
    Write-Host "`nTOTAL SYSTEM HANDLES: $totalHandles" -ForegroundColor Yellow

    Start-Sleep -Seconds 5
}
