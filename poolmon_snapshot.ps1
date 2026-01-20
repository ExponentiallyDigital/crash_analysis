# poolmon_snapshot.ps1
# Run as SYSTEM or elevated. Adjust paths and settings below.
# PURPOSE: Capture raw poolmon data at regular intervals for later analysis.
# NOTE: Raw files accumulate quickly (96/day at 15-min intervals).
#       Monitor disk space or implement periodic cleanup.

$poolmonPath = "C:\perflogs\apps\poolmon.exe"
$outDir      = "C:\perflogs\poolmon"
$iterationInterval = 900 # 15 minutes (900 seconds)

# Check if running as administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Error: script needs to be run as an administrator." -ForegroundColor Red
    exit 1
}

# Check if poolmon.exe exists
if (-not (Test-Path $poolmonPath)) {
    Write-Host "poolmon.exe not found at $poolmonPath. Please verify the path." -ForegroundColor Red
    exit 1
}

# Ensure output dir exists
if (-not (Test-Path $outDir)) { 
    New-Item -ItemType Directory -Path $outDir | Out-Null 
}

Write-Host "Script started. Output directory: $outDir" -ForegroundColor Green
Write-Host "Capture interval: $iterationInterval seconds ($($iterationInterval/60) minutes)" -ForegroundColor Green

$running = $true
try {
    # --- INFINITE LOOP ---
    while ($running) {
        $ts = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $rawFile = Join-Path $outDir "$ts`_poolmon_raw.txt"
        Write-Host "`nStarting poolmon capture at $ts" -ForegroundColor Yellow

        # Start poolmon process
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $poolmonPath
        $startInfo.Arguments = "-b -n `"$rawFile`""
        $startInfo.RedirectStandardOutput = $false
        $startInfo.RedirectStandardError = $false
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true

        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $startInfo
        $proc.Start() | Out-Null

        Write-Host "Sleeping for $iterationInterval seconds ($($iterationInterval/60) minutes). Press Ctrl+C to quit." -ForegroundColor Magenta
        try {
            Start-Sleep -Seconds $iterationInterval
        } catch [System.Management.Automation.PipelineStoppedException] {
            Write-Host "Interrupted by Ctrl+C. Exiting." -ForegroundColor Yellow
            $running = $false
            break
        }
    }
}
catch {
    $ts = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    "Error: $($_.Exception.Message)" | Out-File -FilePath (Join-Path $outDir "poolmon_error_$ts.txt") -Encoding utf8
    Write-Host "Error occurred: $($_.Exception.Message)" -ForegroundColor Red
}
finally {
    Write-Host "`nScript exiting." -ForegroundColor Blue
}