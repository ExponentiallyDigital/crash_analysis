# driver_test_phases.ps1
# Systematic driver elimination for secure kernel crash diagnosis
# Run as Administrator

param(
    [int]$Phase = 0,  # 0 = show menu, 1-6 = run specific phase
    [switch]$Apply
)

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Error: Must run as Administrator" -ForegroundColor Red
    exit 1
}

# Define test phases based on crash likelihood
# !!!!!!!!!!!!! 
# !!!!!!!!!!!!! add/edit entries as needed below
# !!!!!!!!!!!!! 
$TestPhases = @{
    1 = @{
        Name = "NVIDIA GPU Driver Only"
        Description = "Most likely culprit - complex driver with secure kernel interactions"
        Drivers = @('nvlddmkm.sys')
        Risk = "HIGH"
    }
    2 = @{
        Name = "AMD Platform Security (PSP)"
        Description = "Platform Security Processor - direct secure kernel interaction"
        Drivers = @('amdpsp.sys')
        Risk = "HIGH"
    }
    3 = @{
        Name = "Malwarebytes Suite"
        Description = "Security software with kernel-mode components"
        Drivers = @('mbae.sys', 'mbam.sys', 'mbamchameleon.sys', 'mbamswissarmy.sys', 'mwac.sys')
        Risk = "MEDIUM-HIGH"
    }
    4 = @{
        Name = "AMD GPIO/I2C Drivers"
        Description = "Low-level hardware drivers with DMA access"
        Drivers = @('amdgpio2.sys', 'amdgpio3.sys', 'amdi2c.sys', 'amdppkg.sys')
        Risk = "MEDIUM"
    }
    5 = @{
        Name = "Logitech Gaming Peripherals"
        Description = "Virtual HID and enumeration drivers"
        Drivers = @('logi_joy_bus_enum.sys', 'logi_joy_vir_hid.sys', 'logi_joy_xlcore.sys', 'logi_lamparray.sys')
        Risk = "MEDIUM"
    }
    6 = @{
        Name = "Realtek USB & Network Filters"
        Description = "USB controllers and network filter drivers"
        Drivers = @('rtu56cx22x64.sys', 'rtusba64.sys', 'adgnetworkwfpdrv.sys', 'farflt11.sys')
        Risk = "LOW-MEDIUM"
    }
    7 = @{
        Name = "AMD Graphics Cache & Compat"
        Description = "Graphics-related AMD drivers"
        Drivers = @('amd3dvcache.sys', 'amdappcompat.sys')
        Risk = "LOW"
    }
    8 = @{
        Name = "Miscellaneous (e2fn)"
        Description = "Remaining driver (e2fn.sys - unknown)"
        Drivers = @('e2fn.sys')
        Risk = "UNKNOWN"
    }
}

function Show-Menu {
    Write-Host "`n=== DRIVER VERIFIER TEST PHASES ===" -ForegroundColor Cyan
    Write-Host "Systematic elimination to identify secure kernel crash culprit`n" -ForegroundColor Gray
    
    Write-Host "CURRENT VERIFIER STATUS:" -ForegroundColor Yellow
    & verifier /query | Select-String -Pattern "Verified Drivers:|Level:"
    Write-Host ""
    
    Write-Host "RECOMMENDED TEST SEQUENCE:" -ForegroundColor Green
    foreach ($PhaseNum in 1..8 | Sort-Object) {
        $Phase = $TestPhases[$PhaseNum]
        $Color = switch ($Phase.Risk) {
            "HIGH" { "Red" }
            "MEDIUM-HIGH" { "Yellow" }
            "MEDIUM" { "Cyan" }
            "LOW-MEDIUM" { "Gray" }
            "LOW" { "DarkGray" }
            default { "White" }
        }
        
        Write-Host "  Phase $PhaseNum`: " -NoNewline -ForegroundColor White
        Write-Host "$($Phase.Name) " -NoNewline -ForegroundColor $Color
        Write-Host "[$($Phase.Risk)]" -ForegroundColor $Color
        Write-Host "     Drivers: $($Phase.Drivers -join ', ')" -ForegroundColor DarkGray
        Write-Host "     $($Phase.Description)" -ForegroundColor DarkGray
        Write-Host ""
    }
    
    Write-Host "USAGE:" -ForegroundColor Yellow
    Write-Host "  .\driver_test_phases.ps1 -Phase <1-8>        # Show phase details" -ForegroundColor Gray
    Write-Host "  .\driver_test_phases.ps1 -Phase <1-8> -Apply # Apply verifier settings" -ForegroundColor Gray
    Write-Host "`nSTRATEGY:" -ForegroundColor Cyan
    Write-Host "  1. Start with Phase 1 (NVIDIA)" -ForegroundColor Gray
    Write-Host "  2. Run system normally until crash or 12+ hours stable" -ForegroundColor Gray
    Write-Host "  3. If crash: analyze, if stable: move to next phase" -ForegroundColor Gray
    Write-Host "  4. Combine phases if needed (e.g., Phase 1+2 together)" -ForegroundColor Gray
}

function Show-Phase($PhaseNum) {
    if (-not $TestPhases.ContainsKey($PhaseNum)) {
        Write-Host "Error: Invalid phase number. Use 1-8." -ForegroundColor Red
        return
    }
    
    $Phase = $TestPhases[$PhaseNum]
    
    Write-Host "`n=== PHASE $PhaseNum`: $($Phase.Name) ===" -ForegroundColor Cyan
    Write-Host "Risk Level: $($Phase.Risk)" -ForegroundColor Yellow
    Write-Host "Description: $($Phase.Description)" -ForegroundColor Gray
    Write-Host "`nDrivers to verify:" -ForegroundColor White
    foreach ($Driver in $Phase.Drivers) {
        Write-Host "  - $Driver" -ForegroundColor Cyan
    }
    
    Write-Host "`nVerifier command:" -ForegroundColor Yellow
    $DriverList = $Phase.Drivers -join ' '
    $Command = "verifier /flags 0x83B /driver $DriverList"
    Write-Host "  $Command" -ForegroundColor White
    
    if ($Apply) {
        Write-Host "`nApplying verifier settings..." -ForegroundColor Green
        try {
            # First, reset verifier to clear existing settings
            & verifier /reset 2>&1 | Out-Null
            Start-Sleep -Seconds 2
            
            # Apply new settings
            $Drivers = $Phase.Drivers
            & verifier /flags 0x83B /driver $Drivers
            
            Write-Host "[SUCCESS] Verifier configured for Phase $PhaseNum" -ForegroundColor Green
            Write-Host "`nCurrent settings:" -ForegroundColor Yellow
            & verifier /querysettings
            
            Write-Host "`n*** REBOOT REQUIRED ***" -ForegroundColor Red
            Write-Host "After reboot, run system normally and monitor for crashes." -ForegroundColor Yellow
            Write-Host "`nTo check status after reboot:" -ForegroundColor Cyan
            Write-Host "  verifier /query" -ForegroundColor Gray
            
        } catch {
            Write-Host "[ERROR] Failed to configure verifier: $($_.Exception.Message)" -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "`nTo apply these settings, add -Apply flag:" -ForegroundColor Yellow
        Write-Host "  .\driver_test_phases.ps1 -Phase $PhaseNum -Apply" -ForegroundColor Cyan
    }
}

# Main execution
if ($Phase -eq 0) {
    Show-Menu
} elseif ($Phase -ge 1 -and $Phase -le 8) {
    Show-Phase $Phase
} else {
    Write-Host "Error: Phase must be between 1 and 8" -ForegroundColor Red
    Show-Menu
}