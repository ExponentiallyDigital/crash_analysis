# Check for admin rights
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "This script must be run as Administrator. Please re-run in an elevated PowerShell session." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# !!!!!!!!!!!!!
# !!!!!!!!!!!!! edit below lines:
# !!!!!!!!!!!!!
# Eleven page file numbers (PFNs) to be excluded from Windows 11 memory allocation
$pfns = @(
    0x125A0D, 0x125A0E, 0x125A0F, 0x125A10, 0x125A11, 
    0x125A12, 0x125A13, 0x125A14, 0x13C840, 0x13C841, 0x13C842
)

# Create a byte array (8 bytes per 64-bit integer)
$bytes = New-Object byte[] ($pfns.Length * 8)

# Convert each PFN to a 64-bit Little Endian byte sequence
for ($i = 0; $i -lt $pfns.Length; $i++) {
    [BitConverter]::GetBytes([long]$pfns[$i]).CopyTo($bytes, $i * 8)
}

# Ensure the WHEA key exists and write the BadPages binary blob
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\WHEA"
if (!(Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
Set-ItemProperty -Path $registryPath -Name "BadPages" -Value $bytes -Type Binary

Write-Host "WHEA BadPages registry key updated successfully!" -ForegroundColor Green