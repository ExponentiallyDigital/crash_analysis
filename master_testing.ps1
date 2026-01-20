# --- ADMIN CHECK START ---
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "########################################################" -ForegroundColor Red
    Write-Host "ERROR: THIS SCRIPT MUST BE RUN AS ADMINISTRATOR." -ForegroundColor Red
    Write-Host "########################################################" -ForegroundColor Red
    Write-Host "EXIT WITH CTRL+C" -ForegroundColor Yellow
    while ($true) { Start-Sleep -Seconds 1 }   # Only Ctrl+C breaks this
}
# --- ADMIN CHECK END ---

Set-Location "C:\Users\andrew\Documents\crash_analysis"

# 1. RUN THE ONE-TIME SETUP SCRIPT (Verifier Status)
Write-Host ">>> STEP 1: Running Driver Verifier Status Check..." -ForegroundColor Cyan
& ".\verifier_status.ps1"


Write-Host "`n>>> STEP 2: Starting background monitors..." -ForegroundColor Cyan

# Start background monitors
$ProcLeak = Start-Process powershell -ArgumentList "-File", ".\leak_data_logging.ps1" -WindowStyle Normal -PassThru
$ProcPool = Start-Process powershell -ArgumentList "-File", ".\poolmon_snapshot.ps1" -WindowStyle Normal -PassThru

Write-Host "----------------------------------------------------------" -ForegroundColor Green
Write-Host "MONITORING IS ACTIVE (PIDs: $($ProcLeak.Id), $($ProcPool.Id))" -ForegroundColor Green
Write-Host "Look for the '.' dots in the other windows to confirm life."
Write-Host "----------------------------------------------------------" -ForegroundColor Green
Write-Host "Press CTRL+C in THIS window to stop all logging and exit..." -ForegroundColor Yellow

try {
    # Wait forever, ONLY Ctrl+C interrupts this
    while ($true) { Start-Sleep -Seconds 1 }
}
finally {
    Write-Host "`nStopping monitors..." -ForegroundColor Red

    Stop-Process -Id $ProcLeak.Id -Force -ErrorAction SilentlyContinue
    Stop-Process -Id $ProcPool.Id -Force -ErrorAction SilentlyContinue

    if (Test-Path "C:\perflogs\poolmon_snapshot.lock") { 
        Remove-Item "C:\perflogs\poolmon_snapshot.lock" -Force 
    }

    Write-Host "Testing Complete. All windows closed." -ForegroundColor Green
}
