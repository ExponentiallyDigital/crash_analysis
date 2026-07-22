<#
.SYNOPSIS
  Physical address correlation using !pte (does not require DirBase).
  Extracts kernel VAs from 0x139 crashes and translates via !pte.
#>

param(
    [Parameter(Mandatory)]
    [string]$DumpFolder,
    [Parameter(Mandatory)]
    [string]$OutputFolder,
    [string]$CDB = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe",
    [string]$SymbolPath = "srv*C:\Symbols*https://msdl.microsoft.com/download/symbols"
)

if (-not (Test-Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder | Out-Null
}

function Invoke-Cdb {
    param([string]$DumpPath, [string]$Commands)
    $arguments = "-z `"$DumpPath`" -y `"$SymbolPath`" -c `"$Commands; q`""
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $CDB
    $psi.Arguments = $arguments
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    $proc.Start() | Out-Null
    $out = $proc.StandardOutput.ReadToEnd()
    $proc.WaitForExit()
    ($out -split "`r`n|`n") | ForEach-Object { $_.TrimEnd() } | Where-Object { $_ -ne '' }
}

function Is-KernelVA([string]$hex) {
    $clean = $hex.Replace('`','').ToLower()
    return $clean -match '^0xffff[89a-f][0-9a-f]{11}$'
}

# Convert VA + PFN to physical address
function PFN-To-Physical([string]$pfnStr, [string]$va) {
    try {
        $pfn = [Convert]::ToInt64($pfnStr, 16)
        $vaInt = [Convert]::ToInt64(($va -replace '^0x'), 16)
        $phys = ($pfn * 0x1000) + ($vaInt -band 0xFFF)
        return "0x{0:X}" -f $phys
    } catch { return $null }
}

$dumps = Get-ChildItem -Path $DumpFolder -Filter *.dmp | Sort-Object Name
$allResults = @()

foreach ($dump in $dumps) {
    $dumpPath = $dump.FullName
    $baseName = $dump.BaseName
    Write-Host "`n===== Processing $($dump.Name) =====" -ForegroundColor Yellow

    $analyzeLines = Invoke-Cdb -DumpPath $dumpPath -Commands ".symfix; .reload /f; !analyze -v"
    $analyzeLines | Set-Content -Path (Join-Path $OutputFolder "$baseName-analyze.log")

    # BugCheck code
    $bugCheckCode = $null
    $codeLine = $analyzeLines | Where-Object { $_ -match 'BUGCHECK_CODE:\s+([0-9A-Fa-f]+)' }
    if ($codeLine) { $bugCheckCode = "0x$($Matches[1])" }
    Write-Host "BugCheck: $bugCheckCode"

    # Collect kernel VAs from stack (the faulting IP is included in stack, but we'll also grab explicit faulting IP)
    $vas = [System.Collections.ArrayList]@()

    # Faulting IP from TRAP_FRAME
    $ripMatch = $analyzeLines | Where-Object { $_ -match 'rip=([0-9a-fA-F`]+)' } | Select-Object -First 1
    if ($ripMatch) {
        $fip = "0x" + ($Matches[1] -replace '[^0-9a-fA-F]')
        if (Is-KernelVA $fip) { $vas.Add($fip) | Out-Null; Write-Host "  FaultIP: $fip" }
    }

    # Stack lines
    $inStack = $false
    foreach ($line in $analyzeLines) {
        if ($line -match '^STACK_TEXT:') { $inStack = $true; continue }
        if ($inStack -and $line -match '^[A-Z_]+:') { break }
        if ($inStack) {
            # Extract all kernel VAs (take up to 5 unique)
            $hexMatches = [regex]::Matches($line, '([0-9a-fA-F`]{12,17})')
            foreach ($m in $hexMatches) {
                $candidate = "0x" + ($m.Value -replace '[^0-9a-fA-F]')
                if (Is-KernelVA $candidate -and $vas.Count -lt 6 -and $vas -notcontains $candidate) {
                    $vas.Add($candidate) | Out-Null
                    Write-Host "  Stack VA: $candidate"
                }
            }
        }
    }

    if ($vas.Count -eq 0) {
        Write-Warning "No kernel VAs found."
        continue
    }

    # Translate each VA using !pte
    $translations = @()
    $firstPte = $true
    foreach ($va in $vas) {
        $pteLines = Invoke-Cdb -DumpPath $dumpPath -Commands "!pte $va"
        $raw = $pteLines -join "`n"
        if ($firstPte) {
            Write-Host "  Raw !pte for $va :`n$raw"   # show one sample
            $firstPte = $false
        }

        $pfn = $null
        if ($raw -match '(?i)pfn\s+([0-9a-f]+)') {
            $pfn = "0x$($Matches[1])"
        } elseif ($raw -match '(?i)contains\s+([0-9a-f]+)') {
            $pfn = "0x$($Matches[1])"
        }

        $phys = if ($pfn) { PFN-To-Physical $pfn $va } else { $null }
        Write-Host "    $va -> PFN: $pfn  Physical: $phys"
        $translations += [PSCustomObject]@{ VirtualAddress=$va; PFN=$pfn; PhysicalAddress=$phys }
    }

    $allResults += [PSCustomObject]@{
        DumpFile = $dump.Name
        BugCheckCode = $bugCheckCode
        Translations = $translations
    }
}

# Correlation
Write-Host "`n===== All Physical Addresses ====="
$physMap = @{}
foreach ($r in $allResults) {
    foreach ($t in $r.Translations) {
        if ($t.PhysicalAddress) {
            $key = $t.PhysicalAddress
            if (-not $physMap.ContainsKey($key)) { $physMap[$key] = @() }
            $physMap[$key] += [PSCustomObject]@{ Dump=$r.DumpFile; VA=$t.VirtualAddress }
            Write-Host "$($r.DumpFile): $($t.VirtualAddress) -> $key"
        }
    }
}

$correlations = $physMap.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 }
$corrCsv = Join-Path $OutputFolder "PhysicalAddress-Correlations.csv"
if ($correlations) {
    $rows = $correlations | ForEach-Object {
        $addr = $_.Key; $_.Value | ForEach-Object {
            [PSCustomObject]@{ PhysicalAddress=$addr; DumpFile=$_.Dump; VirtualAddress=$_.VA; OccurrenceCount=$_.Value.Count }
        }
    }
    $rows | Export-Csv -Path $corrCsv -NoTypeInformation -Encoding UTF8
    Write-Host "`nRepeated physical addresses saved to $corrCsv"
} else {
    "PhysicalAddress,DumpFile,VirtualAddress,OccurrenceCount" | Out-File -FilePath $corrCsv -Encoding UTF8
    Write-Host "No physical address appeared in more than one dump."
}

Write-Host "Done."