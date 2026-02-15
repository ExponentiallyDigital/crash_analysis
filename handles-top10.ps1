while($true) {
    # Gather data first
    $data = Get-Process | Sort-Object Handles -Descending | Select-Object -First 10 Name, Handles, Id
    
    # Refresh screen
    Clear-Host
    Write-Host "---- TOP 10 HANDLES ----" -ForegroundColor Cyan
    Write-Host "------------------------" -ForegroundColor Gray
    
    # Force immediate display
    $data | Format-Table -AutoSize | Out-Host
    Write-Host "------------------------" -ForegroundColor Gray
    Write-Host "Last Checked: $(Get-Date -Format 'HH:mm:ss')"
    Write-Host "Press Ctrl+C to stop."
    
    Start-Sleep -Seconds 30
}