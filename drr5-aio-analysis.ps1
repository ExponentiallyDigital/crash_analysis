<#
.SYNOPSIS
  Extracts potential corrupted‑memory addresses from 0x139 crashes
  (timer objects only, excluding kernel‑code pages). No crash‑path output.
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
    ($out -split "`r`n|`n") |
        Where-Object { $_ -notmatch 'NatVis|Debugger Extension|Repository|Preparing|Waiting|Microsoft \(R\)|Loading Dump|Symbol search|Executable search|Windows 10 Kernel|Product:|Edition build|Kernel base|Debug session|System Uptime|Loading Kernel|Loading User|Loading unloaded|For analysis|kd>|quit:' } |
        ForEach-Object { $_.TrimEnd() } |
        Where-Object { $_ -ne '' }
}

function Is-KernelVA([string]$hex) {
    $clean = $hex.Replace('`','').ToLower()
    return $clean -match '^0xffff[89a-f][0-9a-f]{11}$'
}

function PFN-To-Physical([string]$pfnStr, [string]$va) {
    try {
        $pfn = [Convert]::ToInt64($pfnStr, 16)
        $vaInt = [Convert]::ToInt64(($va -replace '^0x'), 16)
        return "0x{0:X}" -f (($pfn * 0x1000) + ($vaInt -band 0xFFF))
    } catch { return $null }
}

$dumps = Get-ChildItem -Path $DumpFolder -Filter *.dmp | Sort-Object Name
$allTimers = @()   # only timer objects (no stack code)

foreach ($dump in $dumps) {
    $dumpPath = $dump.FullName
    Write-Host "`n===== Processing $($dump.Name) =====" -ForegroundColor Yellow

    # Quick analyze to confirm bugcheck
    $analyzeLines = Invoke-Cdb -DumpPath $dumpPath -Commands ".symfix; .reload /f; !analyze -v"
    $bugCheckCode = $null
    $codeLine = $analyzeLines | Where-Object { $_ -match 'BUGCHECK_CODE:\s+([0-9A-Fa-f]+)' }
    if ($codeLine) { $bugCheckCode = "0x$($Matches[1])" }
    Write-Host "BugCheck: $bugCheckCode"

    # Extract timer objects
    $timerLines = Invoke-Cdb -DumpPath $dumpPath -Commands "!timer"
    $timerVAs = @()
    foreach ($tl in $timerLines) {
        $hexMatches = [regex]::Matches($tl, '([0-9a-fA-F`]{12,17})')
        foreach ($m in $hexMatches) {
            $candidate = "0x" + ($m.Value -replace '[^0-9a-fA-F]')
            if (Is-KernelVA $candidate -and $timerVAs -notcontains $candidate) {
                $timerVAs += $candidate
            }
        }
    }

    Write-Host "  Timer VAs to translate: $($timerVAs.Count)"

    # Translate only timer VAs, skip PFN 0x200 (kernel code)
    $countTranslated = 0
    foreach ($va in $timerVAs) {
        $pteLines = Invoke-Cdb -DumpPath $dumpPath -Commands "!pte $va"
        $raw = $pteLines -join "`n"
        $pfn = $null
        if ($raw -match '(?i)pfn\s+([0-9a-f]+)') { $pfn = "0x$($Matches[1])" }
        elseif ($raw -match '(?i)contains\s+([0-9a-f]+)') { $pfn = "0x$($Matches[1])" }
        if (-not $pfn) { continue }

        # Exclude PFN 0x200 (kernel code / dispatcher data)
        if ($pfn -eq "0x200") { continue }

        $phys = PFN-To-Physical $pfn $va
        if ($phys) {
            $allTimers += [PSCustomObject]@{ Dump = $dump.Name; VA = $va; Physical = $phys }
            Write-Host "    $va -> $phys  (PFN $pfn)"
            $countTranslated++
        }
    }
    if ($countTranslated -eq 0) {
        Write-Host "    No non‑code timer objects found (all timer VAs in kernel code page)."
    }
}

# ----- Report only timer objects, sorted by physical -----
Write-Host "`n===== Timer Objects (non‑code pages) ====="
if ($allTimers.Count -gt 0) {
    $allTimers = $allTimers | Sort-Object Physical, Dump
    $allTimers | ForEach-Object {
        Write-Host ("{0}: {1} -> {2}" -f $_.Dump, $_.VA, $_.Physical)
    }

    # Correlation across dumps
    $physGroups = $allTimers | Group-Object Physical | Where-Object { $_.Count -gt 1 }
    $corrCsv = Join-Path $OutputFolder "PhysicalAddress-Correlations.csv"
    if ($physGroups) {
        $corrRows = $physGroups | ForEach-Object {
            $phys = $_.Name
            $occ  = $_.Count
            $_.Group | Sort-Object Dump | ForEach-Object {
                [PSCustomObject]@{
                    PhysicalAddress = $phys
                    DumpFile        = $_.Dump
                    VirtualAddress  = $_.VA
                    OccurrenceCount = $occ
                }
            }
        } | Sort-Object PhysicalAddress, DumpFile
        $corrRows | Export-Csv -Path $corrCsv -NoTypeInformation -Encoding UTF8
        Write-Host "`nRepeated timer physical addresses saved to $corrCsv"
    } else {
        Write-Host "`nNo physical address appeared in more than one dump (timers only)."
        "PhysicalAddress,DumpFile,VirtualAddress,OccurrenceCount" | Out-File -FilePath $corrCsv -Encoding UTF8
    }
} else {
    Write-Host "No non‑code timer objects found in any dump."
}

Write-Host "`nDone."