<#
.SYNOPSIS
  Extracts candidate corrupted-memory addresses from 0x139
  KERNEL_SECURITY_CHECK_FAILURE dumps by reading the actual fault context
  (trap frame / exception record from BUGCHECK_P2 / BUGCHECK_P3), rather
  than scanning every live timer object. Correlates resulting physical
  addresses across multiple dump files, both exact matches and near
  misses within a configurable byte distance.

.NOTES
  v3 changes from the previous version:
    - Code/data page exclusion now checks each candidate VA against the
      full address range of every loaded module (from lm), not just
      whether ln resolves it to a named function. The v2 filter missed
      addresses inside a module's data/rodata sections because those
      often aren't symbolized, which let kernel-image addresses (e.g.
      early low-physical-memory structures) leak through as false
      "recurring" hits.
    - dps output parsing now only takes the VALUE column (second hex
      token per line), not the stack slot's own address (first hex
      token). The old regex captured both, which produced long runs of
      addresses incrementing by 8 - that was just each dump's own stack
      being read back, not distinct pointers.
    - Added proximity correlation (PhysicalAddress-NearMatches.csv) in
      addition to exact-match correlation, since ASLR/physical frame
      selection differs per boot and a genuine repeat hit on a bad DRAM
      cell may land at slightly different addresses within the same
      general area rather than bit-for-bit identical ones.
#>

param(
    [Parameter(Mandatory)]
    [string]$DumpFolder,
    [Parameter(Mandatory)]
    [string]$OutputFolder,
    [string]$CDB = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe",
    [string]$SymbolPath = "srv*C:\Symbols*https://msdl.microsoft.com/download/symbols",
    [int64]$ProximityThresholdBytes = 0x10000
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

function Get-HexClean([string]$hex) {
    if (-not $hex) { return $null }
    return ($hex -replace '`', '').Trim()
}

function Is-ZeroOrEmpty([string]$hex) {
    if (-not $hex) { return $true }
    $clean = (Get-HexClean $hex) -replace '^0x'
    return ($clean -match '^0+$')
}

function Is-KernelVA([string]$hex) {
    $clean = (Get-HexClean $hex) -replace '^0x', ''
    $clean = $clean.ToLower()
    if ($clean.Length -lt 12) { return $false }
    return ("0x$clean") -match '^0xffff[89a-f][0-9a-f]{11}$'
}

function Hex-ToInt64([string]$hex) {
    $clean = (Get-HexClean $hex) -replace '^0x'
    return [Convert]::ToInt64($clean, 16)
}

function Get-PfnFromPte([string[]]$pteLines) {
    $raw = $pteLines -join "`n"
    if ($raw -match '(?im)^\s*pfn\s+([0-9a-f]+)') { return $Matches[1] }
    return $null
}

function PFN-To-Physical([string]$pfnStr, [string]$va) {
    try {
        $pfn = Hex-ToInt64 $pfnStr
        $vaInt = Hex-ToInt64 $va
        return "0x{0:X}" -f (($pfn * 0x1000) + ($vaInt -band 0xFFF))
    } catch { return $null }
}

function Get-ModuleRanges([string]$dumpPath) {
    $lmLines = Invoke-Cdb -DumpPath $dumpPath -Commands "lm"
    $ranges = @()
    foreach ($line in $lmLines) {
        if ($line -match '^\s*([0-9a-fA-F`]{8,17})\s+([0-9a-fA-F`]{8,17})\s+(\S+)') {
            try {
                $start = Hex-ToInt64 $Matches[1]
                $end   = Hex-ToInt64 $Matches[2]
                $ranges += [PSCustomObject]@{ Start = $start; End = $end; Name = $Matches[3] }
            } catch { }
        }
    }
    return $ranges
}

function Is-InAnyModule([int64]$vaInt, $moduleRanges) {
    foreach ($r in $moduleRanges) {
        if ($vaInt -ge $r.Start -and $vaInt -le $r.End) { return $true }
    }
    return $false
}

$dumps = Get-ChildItem -Path $DumpFolder -Filter *.dmp | Sort-Object Name
$results = @()

foreach ($dump in $dumps) {
    $dumpPath = $dump.FullName
    Write-Host "`n===== Processing $($dump.Name) =====" -ForegroundColor Yellow

    $analyzeLines = Invoke-Cdb -DumpPath $dumpPath -Commands ".symfix; .reload /f; !analyze -v"
    $joinedAnalyze = $analyzeLines -join "`n"

    $bugCheckCode = $null
    if ($joinedAnalyze -match '(?im)^BUGCHECK_CODE:\s+([0-9A-Fa-f]+)') { $bugCheckCode = "0x$($Matches[1])" }

    $p1 = $null; $p2 = $null; $p3 = $null
    if ($joinedAnalyze -match '(?im)^BUGCHECK_P1:\s+([0-9A-Fa-f]+)') { $p1 = $Matches[1] }
    if ($joinedAnalyze -match '(?im)^BUGCHECK_P2:\s+([0-9A-Fa-f]+)') { $p2 = $Matches[1] }
    if ($joinedAnalyze -match '(?im)^BUGCHECK_P3:\s+([0-9A-Fa-f]+)') { $p3 = $Matches[1] }

    Write-Host "  BugCheck: $bugCheckCode  P1(type): $p1  TrapFrame: $p2  ExceptionRecord: $p3"

    if ($bugCheckCode -ne "0x139") {
        Write-Host "  Skipping - not a 0x139 bugcheck." -ForegroundColor DarkGray
        continue
    }
    if (Is-ZeroOrEmpty $p2) {
        Write-Host "  No usable trap frame address - skipping this dump." -ForegroundColor DarkYellow
        continue
    }

    $moduleRanges = Get-ModuleRanges -dumpPath $dumpPath
    Write-Host "  Loaded module ranges captured: $($moduleRanges.Count)"

    $trapCmd = if (-not (Is-ZeroOrEmpty $p3)) {
        ".trap 0x$p2; .exr 0x$p3; r; dps @rsp L10"
    } else {
        ".trap 0x$p2; r; dps @rsp L10"
    }
    $ctxLines = Invoke-Cdb -DumpPath $dumpPath -Commands $trapCmd

    $candidateVAs = @()
    foreach ($line in $ctxLines) {
        if ($line -match '=') {
            $hexMatches = [regex]::Matches($line, '([0-9a-fA-F`]{12,17})')
            foreach ($m in $hexMatches) {
                $candidate = "0x" + (Get-HexClean $m.Value)
                if ((Is-KernelVA $candidate) -and ($candidateVAs -notcontains $candidate)) {
                    $candidateVAs += $candidate
                }
            }
        }
        elseif ($line -match '^\s*[0-9a-fA-F`]{8,17}\s+([0-9a-fA-F`]{8,17})') {
            $candidate = "0x" + (Get-HexClean $Matches[1])
            if ((Is-KernelVA $candidate) -and ($candidateVAs -notcontains $candidate)) {
                $candidateVAs += $candidate
            }
        }
    }

    Write-Host "  Candidate kernel VAs from fault context: $($candidateVAs.Count)"

    foreach ($va in $candidateVAs) {
        $vaInt = Hex-ToInt64 $va
        if (Is-InAnyModule $vaInt $moduleRanges) { continue }

        $pteLines = Invoke-Cdb -DumpPath $dumpPath -Commands "!pte $va"
        $pfn = Get-PfnFromPte $pteLines
        if (-not $pfn) { continue }

        $phys = PFN-To-Physical $pfn $va
        if ($phys) {
            $results += [PSCustomObject]@{
                Dump           = $dump.Name
                CorruptionType = $p1
                VA             = $va
                Physical       = $phys
                PhysicalInt    = Hex-ToInt64 $phys
            }
        }
    }
}

Write-Host "`n===== Fault-Context Candidate Physical Addresses ====="
if ($results.Count -gt 0) {
    $results = $results | Sort-Object Physical, Dump

    $allCsv = Join-Path $OutputFolder "FaultContext-Candidates.csv"
    $results | Select-Object Dump, CorruptionType, VA, Physical |
        Export-Csv -Path $allCsv -NoTypeInformation -Encoding UTF8
    Write-Host "All candidates (post module-range filtering) saved to $allCsv"

    $physGroups = $results | Group-Object Physical | Where-Object { $_.Count -gt 1 }
    $corrCsv = Join-Path $OutputFolder "PhysicalAddress-Correlations.csv"
    if ($physGroups) {
        $corrRows = $physGroups | ForEach-Object {
            $phys = $_.Name
            $occ  = $_.Count
            $_.Group | Sort-Object Dump | ForEach-Object {
                [PSCustomObject]@{
                    PhysicalAddress = $phys
                    DumpFile        = $_.Dump
                    CorruptionType  = $_.CorruptionType
                    VirtualAddress  = $_.VA
                    OccurrenceCount = $occ
                }
            }
        } | Sort-Object PhysicalAddress, DumpFile
        $corrRows | Export-Csv -Path $corrCsv -NoTypeInformation -Encoding UTF8
        Write-Host "`nExact-match physical addresses across dumps saved to $corrCsv"
        $physGroups | ForEach-Object { Write-Host ("  {0}  (seen in {1} dumps)" -f $_.Name, $_.Count) }
    } else {
        Write-Host "`nNo physical address recurred exactly across more than one dump."
        "PhysicalAddress,DumpFile,CorruptionType,VirtualAddress,OccurrenceCount" | Out-File -FilePath $corrCsv -Encoding UTF8
    }

    $nearCsv = Join-Path $OutputFolder "PhysicalAddress-NearMatches.csv"
    $sortedByPhys = $results | Sort-Object PhysicalInt
    $nearRows = @()
    for ($i = 0; $i -lt $sortedByPhys.Count - 1; $i++) {
        for ($j = $i + 1; $j -lt $sortedByPhys.Count; $j++) {
            $a = $sortedByPhys[$i]; $b = $sortedByPhys[$j]
            $dist = $b.PhysicalInt - $a.PhysicalInt
            if ($dist -gt $ProximityThresholdBytes) { break }
            if ($a.Dump -eq $b.Dump) { continue }
            if ($a.Physical -eq $b.Physical) { continue }
            $nearRows += [PSCustomObject]@{
                PhysicalA     = $a.Physical
                DumpA         = $a.Dump
                PhysicalB     = $b.Physical
                DumpB         = $b.Dump
                DistanceBytes = $dist
            }
        }
    }
    if ($nearRows.Count -gt 0) {
        $nearRows | Sort-Object DistanceBytes | Export-Csv -Path $nearCsv -NoTypeInformation -Encoding UTF8
        Write-Host "`nNear-match candidates (within $ProximityThresholdBytes bytes, different dumps) saved to $nearCsv"
        $nearRows | Sort-Object DistanceBytes | Select-Object -First 10 | ForEach-Object {
            Write-Host ("  {0} ({1})  <->  {2} ({3})   distance 0x{4:X}" -f $_.PhysicalA, $_.DumpA, $_.PhysicalB, $_.DumpB, $_.DistanceBytes)
        }
    } else {
        Write-Host "`nNo near-match candidates within $ProximityThresholdBytes bytes across different dumps."
        "PhysicalA,DumpA,PhysicalB,DumpB,DistanceBytes" | Out-File -FilePath $nearCsv -Encoding UTF8
    }

    $typeCsv = Join-Path $OutputFolder "CorruptionType-Summary.csv"
    $results | Select-Object Dump, CorruptionType -Unique |
        Sort-Object Dump |
        Export-Csv -Path $typeCsv -NoTypeInformation -Encoding UTF8
    Write-Host "`nPer-dump corruption type (BUGCHECK_P1) summary saved to $typeCsv"
} else {
    Write-Host "No fault-context candidates found in any 0x139 dump."
}

Write-Host "`nDone."