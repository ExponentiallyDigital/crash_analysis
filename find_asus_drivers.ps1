# 1. Search the Windows Driver Store for any INF files referencing ASUS
Write-Host "Searching Driver Store for ASUS remnants..." -ForegroundColor Cyan
$oemDrivers = Get-WindowsDriver -Online -All | Where-Object { 
    $_.ProviderName -like "*ASUS*" -or 
    $_.OriginalFileName -like "*asus*" 
}

if ($oemDrivers) {
    foreach ($drv in $oemDrivers) {
        Write-Host "`n[!] ASUS DRIVER FOUND" -ForegroundColor Yellow
        Write-Host "  Name:       $($drv.Driver)"
        Write-Host "  Provider:   $($drv.ProviderName)"
        Write-Host "  Class:      $($drv.ClassName)"
        Write-Host "  Version:    $($drv.Version)"
        Write-Host "  Date:       $($drv.Date)"
        Write-Host "  Original:   $($drv.OriginalFileName)"
        
        # Check if the actual .sys binary exists in System32
        $sysName = ($drv.OriginalFileName -split '\\')[-1].Replace(".inf", ".sys")
        $sysPath = "C:\Windows\System32\drivers\$sysName"
        if (Test-Path $sysPath) {
            Write-Host "  Binary:     $sysPath (EXISTS)" -ForegroundColor Green
            $fileInfo = Get-Item $sysPath
            Write-Host "  File Size:  $($fileInfo.Length / 1KB) KB"
        } else {
            Write-Host "  Binary:     $sysName (Binary missing, INF remnant only)" -ForegroundColor Gray
        }
    }
} else {
    Write-Host "No ASUS drivers found in the Windows Driver Store." -ForegroundColor Green
}