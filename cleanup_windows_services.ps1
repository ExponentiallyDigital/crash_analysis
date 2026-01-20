# Get all services via WMI to access the raw PathName
$services = Get-WmiObject -Class Win32_Service

foreach ($svc in $services) {
    $rawPath = $svc.PathName
    if ($null -eq $rawPath -or $rawPath -eq "") { continue }

    # Regex to extract the actual .exe path, ignoring arguments
    # Handles both quoted and unquoted paths
    if ($rawPath -match '^"([^"]+)"' -or $rawPath -match '^([^\s]+)') {
        $cleanPath = $matches[1]
        
        # We only care about non-Windows system drivers (skip C:\Windows\System32 for safety)
        if ($cleanPath -like "C:\*" -and $cleanPath -notlike "*C:\Windows\System32*") {
            
            if (-not (Test-Path -Path $cleanPath -ErrorAction SilentlyContinue)) {
                Write-Host "`n[!] GHOST SERVICE DETECTED" -ForegroundColor Yellow
                Write-Host "Service Name : $($svc.Name)" -ForegroundColor White
                Write-Host "Display Name : $($svc.DisplayName)" -ForegroundColor White
                Write-Host "Missing Path : $cleanPath" -ForegroundColor Gray
                
                # The Prompt
                $title = "Remove Ghost Service"
                $message = "Do you want to permanently delete the service '$($svc.DisplayName)'?"
                $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Removes the service entry from the registry."
                $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Keeps the service."
                $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
                
                $result = $host.ui.PromptForChoice($title, $message, $options, 1) 
                
                if ($result -eq 0) {
                    # Stop the service first to release any registry handles
                    Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
                    # Use sc.exe for a clean registry delete
                    & sc.exe delete $($svc.Name)
                    Write-Host "REMOVED: $($svc.Name)" -ForegroundColor Red
                } else {
                    Write-Host "SKIPPED: $($svc.Name)" -ForegroundColor Cyan
                }
            }
        }
    }
}
Write-Host "`nService Scan Complete." -ForegroundColor Green