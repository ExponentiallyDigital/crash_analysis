$SearchPaths = @("C:\Windows")
# $SearchPaths = @("C:\Windows\System32\drivers", "C:\Program Files", "C:\Program Files (x86)")
$SignerFilter = "ASUSTeK COMPUTER INC."
$fileCount = 0

Write-Host "Starting Deep Signature Scan... (Showing '.' for every file examined)" -ForegroundColor Cyan

foreach ($Path in $SearchPaths) {
    if (Test-Path $Path) {
        $Files = Get-ChildItem -LiteralPath $Path -Include *.exe, *.dll, *.sys -Recurse -File -ErrorAction SilentlyContinue | 
                 Where-Object { $_.FullName -notlike "*\DriverData\*" }
        
        foreach ($File in $Files) {
            $fileCount++
            # Print a dot every file; print the count every 100 files to keep the screen clean
            Write-Host "." -NoNewline
            if ($fileCount % 100 -eq 0) { Write-Host " [$fileCount]" -ForegroundColor Gray }

            try {
                $Signature = Get-AuthenticodeSignature -LiteralPath $File.FullName -ErrorAction Stop
                
                if ($Signature.SignerCertificate.Subject -like "*$SignerFilter*") {
                    Write-Host "`n`n[!] SIGNATURE MATCH: $($File.Name)" -ForegroundColor Yellow
                    Write-Host "Path: $($File.FullName)" -ForegroundColor Gray
                    Write-Host "Signer: $($Signature.SignerCertificate.Subject)"
                    Write-Host "" # New line to resume dots nicely
                }
            }
            catch {
                continue
            }
        }
    }
}
Write-Host "`n`nScan Complete. Total files examined: $fileCount" -ForegroundColor Green