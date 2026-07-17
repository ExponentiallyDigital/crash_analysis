# start_secure_kernel_trace.ps1
# Start Windows Performance Recorder trace for secure kernel debugging
# Run as Administrator

# !!!!!!!!!!!!! 
# !!!!!!!!!!!!! edit below line:
# !!!!!!!!!!!!! 
param(
    [string]$OutputPath = "C:\PerfLogs\SecureKernelTrace",
    [int]$MaxSizeMB = 2048
)

# Check for admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Error: Must run as Administrator" -ForegroundColor Red
    exit 1
}

# Ensure output directory exists
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath | Out-Null
}

Write-Host "=== SECURE KERNEL TRACE SETUP ===" -ForegroundColor Cyan
Write-Host "Output: $OutputPath" -ForegroundColor Gray
Write-Host "Max Size: $MaxSizeMB MB`n" -ForegroundColor Gray

# Stop any existing traces
Write-Host "Stopping existing traces..." -ForegroundColor Yellow
try {
    & wpr.exe -cancel 2>&1 | Out-Null
    Start-Sleep -Seconds 2
} catch {}

# Create custom profile for driver/kernel tracing
$ProfilePath = Join-Path $OutputPath "SecureKernelTrace.wprp"
$ProfileXml = @"
<?xml version="1.0" encoding="utf-8"?>
<WindowsPerformanceRecorder Version="1.0">
  <Profiles>
    <SystemCollector Id="SystemCollector" Name="NT Kernel Logger">
      <BufferSize Value="1024"/>
      <Buffers Value="100"/>
    </SystemCollector>
    
    <SystemProvider Id="SystemProvider">
      <Keywords>
        <Keyword Value="CpuConfig"/>
        <Keyword Value="Loader"/>
        <Keyword Value="ProcessThread"/>
        <Keyword Value="Driver"/>
        <Keyword Value="Memory"/>
        <Keyword Value="MemoryInfo"/>
        <Keyword Value="MemoryInfoWS"/>
        <Keyword Value="Pool"/>
        <Keyword Value="DPC"/>
        <Keyword Value="Interrupt"/>
        <Keyword Value="HardFaults"/>
        <Keyword Value="VirtualAlloc"/>
      </Keywords>
      <Stacks>
        <Stack Value="PoolAllocation"/>
        <Stack Value="PoolAllocationSession"/>
        <Stack Value="VirtualAllocation"/>
      </Stacks>
    </SystemProvider>
    
    <Profile Id="SecureKernelTrace.Verbose.File" Name="SecureKernelTrace" 
             Description="Kernel and driver tracing for secure kernel crashes"
             LoggingMode="File" DetailLevel="Verbose">
      <Collectors>
        <SystemCollectorId Value="SystemCollector">
          <SystemProviderId Value="SystemProvider"/>
        </SystemCollectorId>
      </Collectors>
    </Profile>
  </Profiles>
</WindowsPerformanceRecorder>
"@

Write-Host "Creating trace profile..." -ForegroundColor Yellow
$ProfileXml | Out-File -FilePath $ProfilePath -Encoding UTF8

# Start trace
$TraceFile = Join-Path $OutputPath "SecureKernelTrace_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').etl"

Write-Host "`nStarting WPR trace..." -ForegroundColor Green
Write-Host "  Profile: $ProfilePath" -ForegroundColor Gray
Write-Host "  Output: $TraceFile" -ForegroundColor Gray

try {
    $StartArgs = "-start `"$ProfilePath`" -filemode -recordtempto `"$OutputPath`""
    Start-Process -FilePath "wpr.exe" -ArgumentList $StartArgs -NoNewWindow -Wait
    
    Write-Host "`n[SUCCESS] Trace started" -ForegroundColor Green
    Write-Host "`nTo stop trace and save, run:" -ForegroundColor Yellow
    Write-Host "  wpr.exe -stop `"$TraceFile`"`n" -ForegroundColor Cyan
    
    Write-Host "Trace is now running. Reproduce the crash, then:" -ForegroundColor White
    Write-Host "  1. If system crashes, trace will auto-save" -ForegroundColor Gray
    Write-Host "  2. If no crash, manually stop with command above" -ForegroundColor Gray
    Write-Host "  3. Analyze with: wpa.exe `"$TraceFile`"`n" -ForegroundColor Gray
    
} catch {
    Write-Host "`n[ERROR] Failed to start trace: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}