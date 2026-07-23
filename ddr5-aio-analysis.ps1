<#
.SYNOPSIS
  Extracts candidate corrupted-memory addresses from KERNEL_SECURITY_CHECK_FAILURE
  (0x139), SYSTEM_SERVICE_EXCEPTION (0x3b), and SYSTEM_THREAD_EXCEPTION_NOT_HANDLED
  (0x7e) dumps, and correlates the resulting physical addresses - both exact
  matches and near misses - across multiple dump files.

.NOTES
  v6 changes - fixes two sources of false "candidates":

  1) BUGCHECK_P1-P4 exclusion. The TRAP_FRAME:/CONTEXT: header line itself
     contains the block's own address as literal text (eg
     "CONTEXT:  ffff80818392d8f0 -- (.cxr 0xffff80818392d8f0)"), and for
     0x139 the top STACK_TEXT frame re-prints the bugcheck's own arguments
     as KeBugCheckEx's call parameters. Both leak P1-P4 back into the
     candidate pool as if they were real register/stack values, when
     they're just the debugger's own bookkeeping addresses. Every
     candidate is now checked against P1-P4 (compared numerically, not by
     string, since formatting/leading zeros vary) and dropped if it
     matches.

  2) Hex-token regex tightened. The old pattern ([0-9a-fA-F`]{12,17}) could
     match across two adjacent-but-unrelated hex fields with no separator,
     producing bogus stitched-together values. Candidates are now only
     accepted if they're exactly a 16-hex-digit token (optionally with a
     single backtick after the 8th digit, matching cdb's own address
     formatting), with a lookaround guard so a match can't be a fragment
     of a longer adjacent run of hex/backtick characters.
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

$SupportedBugChecks = @("0x139", "0x3b", "0x7e")

# A hex token is exactly 16 digits, optionally split by one backtick after
# the 8th digit (cdb's own formatting), and must not be adjacent to more
# hex/backtick characters - prevents matching a fragment of a longer run.
$HexTokenCore = '[0-9a-fA-F]{8}`[0-9a-fA-F]{8}|[0-9a-fA-F]{16}'
$HexTokenPattern = "(?<![0-9a-fA-F``])($HexTokenCore)(?![0-9a-fA-F``])"

if (-not (Test-Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder | Out-Null
}

# Returns @{ Lines = [string[]]; TimedOut = [bool] }. Never discards
# whatever was captured before a forced kill.
function Invoke-Cdb {
    param(
        [string]$DumpPath,
        [string]$Commands,
        [int]$TimeoutSeconds = 120
    )
    $arguments = "-z `"$DumpPath`" -y `"$SymbolPath`" -c `"$Commands; q`""
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $CDB
    $psi.Arguments = $arguments
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi

    $stdoutBuilder = New-Object System.Text.StringBuilder
    $stderrBuilder = New-Object System.Text.StringBuilder

    $outEvent = Register-ObjectEvent -InputObject $proc -EventName OutputDataReceived -Action {
        if ($null -ne $EventArgs.Data) { [void]$Event.MessageData.AppendLine($EventArgs.Data) }
    } -MessageData $stdoutBuilder

    $errEvent = Register-ObjectEvent -InputObject $proc -EventName ErrorDataReceived -Action {
        if ($null -ne $EventArgs.Data) { [void]$Event.MessageData.AppendLine($EventArgs.Data) }
    } -MessageData $stderrBuilder

    $timedOut = $false
    try {
        $proc.Start() | Out-Null
        try { $proc.StandardInput.Close() } catch { }
        $proc.BeginOutputReadLine()
        $proc.BeginErrorReadLine()

        $exited = $proc.WaitForExit($TimeoutSeconds * 1000)
        if (-not $exited) {
            $timedOut = $true
            Write-Host "    [TIMEOUT] cdb exceeded ${TimeoutSeconds}s - killing it, using whatever output was captured so far." -ForegroundColor DarkYellow
            try { $proc.Kill() } catch { }
            $proc.WaitForExit(5000) | Out-Null
        }
    } finally {
        Unregister-Event -SourceIdentifier $outEvent.Name -ErrorAction SilentlyContinue
        Unregister-Event -SourceIdentifier $errEvent.Name -ErrorAction SilentlyContinue
        Remove-Job -Name $outEvent.Name -Force -ErrorAction SilentlyContinue
        Remove-Job -Name $errEvent.Name -Force -ErrorAction SilentlyContinue
    }

    $out = $stdoutBuilder.ToString()
    $lines = ($out -split "`r`n|`n") |
        Where-Object { $_ -notmatch 'NatVis|Debugger Extension|Repository|Preparing|Waiting|Microsoft \(R\)|Loading Dump|Symbol search|Executable search|Windows 10 Kernel|Product:|Edition build|Kernel base|Debug session|System Uptime|Loading Kernel|Loading User|Loading unloaded|For analysis|kd>|quit:' } |
        ForEach-Object { $_.TrimEnd() } |
        Where-Object { $_ -ne '' }

    return [PSCustomObject]@{ Lines = @($lines); TimedOut = $timedOut }
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

# Same as Hex-ToInt64 but returns $null instead of throwing, for values
# that might be empty/malformed (eg an argument that wasn't present).
function Try-HexToInt64([string]$hex) {
    if (Is-ZeroOrEmpty $hex) { return $null }
    try { return Hex-ToInt64 $hex } catch { return $null }
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

function Get-ModuleRangesFromLines([string[]]$lmLines) {
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

# Pulls lines from a marker up to a stop pattern or maxLines, whichever
# comes first. Used to read register/stack data straight out of !analyze
# -v's own output rather than re-querying the debugger.
function Get-Section([string[]]$lines, [string]$startPattern, [string[]]$stopPatterns, [int]$maxLines = 20) {
    $capture = @()
    $capturing = $false
    foreach ($line in $lines) {
        if (-not $capturing) {
            if ($line -match $startPattern) { $capturing = $true; $capture += $line }
            continue
        }
        if ($capture.Count -ge $maxLines) { break }
        $stop = $false
        foreach ($sp in $stopPatterns) { if ($line -match $sp) { $stop = $true; break } }
        if ($stop) { break }
        $capture += $line
    }
    return $capture
}

# Broad scan using the strict 16-digit hex token pattern. Fine for
# TRAP_FRAME/CONTEXT ("rax=<hex>" pairs) and STACK_TEXT (return
# addresses/args) - every properly-bounded hex token in those blocks is a
# real value, not a mix of "memory location" and "value stored there".
function Get-CandidatesFromLines([string[]]$lines, [string]$tokenPattern) {
    $found = @()
    foreach ($line in $lines) {
        $hexMatches = [regex]::Matches($line, $tokenPattern)
        foreach ($m in $hexMatches) {
            $candidate = "0x" + (Get-HexClean $m.Groups[1].Value)
            if ((Is-KernelVA $candidate) -and ($found -notcontains $candidate)) { $found += $candidate }
        }
    }
    return $found
}

# Column-aware: dps prints "<stack slot address>  <value>[ symbol]" per
# line. Only the VALUE (2nd column) is a meaningful candidate.
function Get-CandidatesFromDpsLines([string[]]$lines, [string]$tokenCore) {
    $found = @()
    $linePattern = "^\s*(?:$tokenCore)\s+($tokenCore)(?:\s|$)"
    foreach ($line in $lines) {
        if ($line -match $linePattern) {
            $candidate = "0x" + (Get-HexClean $Matches[1])
            if ((Is-KernelVA $candidate) -and ($found -notcontains $candidate)) { $found += $candidate }
        }
    }
    return $found
}

$dumps = Get-ChildItem -Path $DumpFolder -Filter *.dmp | Sort-Object Name
$results = @()

foreach ($dump in $dumps) {
    $dumpPath = $dump.FullName
    Write-Host "`n===== Processing $($dump.Name) =====" -ForegroundColor Yellow

    $analyzeResult = Invoke-Cdb -DumpPath $dumpPath -Commands ".symfix; .reload /f; !analyze -v" -TimeoutSeconds 240
    if ($analyzeResult.TimedOut) {
        Write-Host "  Note: !analyze -v didn't exit cleanly within 240s. Using the output captured before the kill." -ForegroundColor DarkYellow
    }
    $analyzeLines = $analyzeResult.Lines
    $joinedAnalyze = $analyzeLines -join "`n"

    $bugCheckCode = $null
    if ($joinedAnalyze -match '(?im)^BUGCHECK_CODE:\s+([0-9A-Fa-f]+)') { $bugCheckCode = "0x$($Matches[1])" }

    $p1 = $null; $p2 = $null; $p3 = $null; $p4 = $null
    if ($joinedAnalyze -match '(?im)^BUGCHECK_P1:\s+([0-9A-Fa-f]+)') { $p1 = $Matches[1] }
    if ($joinedAnalyze -match '(?im)^BUGCHECK_P2:\s+([0-9A-Fa-f]+)') { $p2 = $Matches[1] }
    if ($joinedAnalyze -match '(?im)^BUGCHECK_P3:\s+([0-9A-Fa-f]+)') { $p3 = $Matches[1] }
    if ($joinedAnalyze -match '(?im)^BUGCHECK_P4:\s+([0-9A-Fa-f]+)') { $p4 = $Matches[1] }

    Write-Host "  BugCheck: $bugCheckCode  P1: $p1  P2: $p2  P3: $p3  P4: $p4"

    if (-not $bugCheckCode) {
        Write-Host "  Skipping - could not determine a bugcheck code even from partial output; dump is likely too damaged to use." -ForegroundColor Red
        continue
    }
    if ($SupportedBugChecks -notcontains $bugCheckCode) {
        Write-Host "  Skipping - $bugCheckCode is not one of the supported codes ($($SupportedBugChecks -join ', '))." -ForegroundColor DarkGray
        continue
    }

    # Values to exclude from the candidate pool: these are the debugger's
    # own bookkeeping addresses (trap frame / exception record / context
    # record locations, or the bugcheck's own P1-P4 arguments), not real
    # register/stack contents. Compared numerically since formatting and
    # leading zeros vary between where they're printed.
    $excludedInts = @($p1, $p2, $p3, $p4) | ForEach-Object { Try-HexToInt64 $_ } | Where-Object { $null -ne $_ }

    $lmResult = Invoke-Cdb -DumpPath $dumpPath -Commands "lm"
    if ($lmResult.TimedOut) {
        Write-Host "  Note: lm timed out - module-range filtering will use whatever partial list was captured." -ForegroundColor DarkYellow
    }
    $moduleRanges = Get-ModuleRangesFromLines $lmResult.Lines
    Write-Host "  Loaded module ranges captured: $($moduleRanges.Count)"

    # Register block header differs by code: 0x139 uses .trap internally and
    # prints "TRAP_FRAME:"; 0x3b/0x7e use .cxr internally and print
    # "CONTEXT:". Same reg=value line format either way. Note the header
    # line itself embeds its own address as text (see NOTES above) - this
    # is exactly what the P1-P4 exclusion below is for.
    $regBlockLines = Get-Section -lines $analyzeLines -startPattern '^(TRAP_FRAME|CONTEXT):' -stopPatterns @('^Resetting default scope', '^EXCEPTION_RECORD:', '^BLACKBOX') -maxLines 12
    $stackTextLines = Get-Section -lines $analyzeLines -startPattern '^STACK_TEXT:' -stopPatterns @('^STACK_COMMAND:') -maxLines 40

    if ($regBlockLines.Count -eq 0) {
        Write-Host "  No TRAP_FRAME/CONTEXT register block found in !analyze -v output - skipping this dump." -ForegroundColor DarkYellow
        continue
    }

    $rspValue = $null
    foreach ($l in $regBlockLines) {
        if ($l -match 'rsp=([0-9a-f]+)') { $rspValue = $Matches[1]; break }
    }

    $candidateVAs = Get-CandidatesFromLines ($regBlockLines + $stackTextLines) $HexTokenPattern

    # Best-effort deeper stack read. dps just reads memory at an address -
    # it doesn't need "current" execution context re-established, so it's
    # safe even where that context is otherwise broken.
    if ($rspValue -and -not (Is-ZeroOrEmpty $rspValue)) {
        $dpsResult = Invoke-Cdb -DumpPath $dumpPath -Commands "dps 0x$rspValue L16" -TimeoutSeconds 30
        if ($dpsResult.TimedOut) {
            Write-Host "  Note: supplementary stack dps timed out - continuing with TRAP_FRAME/CONTEXT + STACK_TEXT candidates only." -ForegroundColor DarkYellow
        }
        $extra = Get-CandidatesFromDpsLines $dpsResult.Lines $HexTokenCore
        foreach ($c in $extra) { if ($candidateVAs -notcontains $c) { $candidateVAs += $c } }
    }

    $preExclusionCount = $candidateVAs.Count
    $candidateVAs = $candidateVAs | Where-Object { $excludedInts -notcontains (Hex-ToInt64 $_) }
    $excludedCount = $preExclusionCount - $candidateVAs.Count
    if ($excludedCount -gt 0) {
        Write-Host "  Excluded $excludedCount candidate(s) matching BUGCHECK_P1-P4 (debugger bookkeeping addresses, not real data)." -ForegroundColor DarkGray
    }

    Write-Host "  Candidate kernel VAs from fault context: $($candidateVAs.Count)"

    foreach ($va in $candidateVAs) {
        $vaInt = Hex-ToInt64 $va
        if (Is-InAnyModule $vaInt $moduleRanges) { continue }

        $pteResult = Invoke-Cdb -DumpPath $dumpPath -Commands "!pte $va" -TimeoutSeconds 30
        if ($pteResult.TimedOut) {
            Write-Host "    [TIMEOUT] !pte $va - skipping this candidate." -ForegroundColor DarkYellow
            continue
        }
        $pfn = Get-PfnFromPte $pteResult.Lines
        if (-not $pfn) { continue }

        $phys = PFN-To-Physical $pfn $va
        if ($phys) {
            $results += [PSCustomObject]@{
                Dump           = $dump.Name
                BugCheckCode   = $bugCheckCode
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
    $results | Select-Object Dump, BugCheckCode, CorruptionType, VA, Physical |
        Export-Csv -Path $allCsv -NoTypeInformation -Encoding UTF8
    Write-Host "All candidates (post module-range + P1-P4 filtering) saved to $allCsv"

    # ----- Exact matches, split by whether all dumps in the group share a bugcheck code -----
    $physGroups = $results | Group-Object Physical | Where-Object { $_.Count -gt 1 }
    $corrCsv = Join-Path $OutputFolder "PhysicalAddress-Correlations.csv"
    if ($physGroups) {
        $corrRows = $physGroups | ForEach-Object {
            $phys = $_.Name
            $occ  = $_.Count
            $codes = $_.Group | Select-Object -ExpandProperty BugCheckCode -Unique
            $matchType = if ($codes.Count -gt 1) { "CrossCode" } else { "SameCode" }
            $_.Group | Sort-Object Dump | ForEach-Object {
                [PSCustomObject]@{
                    PhysicalAddress = $phys
                    MatchType       = $matchType
                    DumpFile        = $_.Dump
                    BugCheckCode    = $_.BugCheckCode
                    CorruptionType  = $_.CorruptionType
                    VirtualAddress  = $_.VA
                    OccurrenceCount = $occ
                }
            }
        } | Sort-Object @{Expression = { if ($_.MatchType -eq "CrossCode") { 0 } else { 1 } }}, PhysicalAddress, DumpFile
        $corrRows | Export-Csv -Path $corrCsv -NoTypeInformation -Encoding UTF8
        Write-Host "`nExact-match physical addresses across dumps saved to $corrCsv"

        $crossGroups = $physGroups | Where-Object { ($_.Group | Select-Object -ExpandProperty BugCheckCode -Unique).Count -gt 1 }
        $sameGroups  = $physGroups | Where-Object { ($_.Group | Select-Object -ExpandProperty BugCheckCode -Unique).Count -eq 1 }

        if ($crossGroups) {
            Write-Host "  CROSS-CODE matches (different failure modes sharing a physical address - strongest signal):" -ForegroundColor Magenta
            $crossGroups | ForEach-Object {
                $codes = ($_.Group | Select-Object -ExpandProperty BugCheckCode -Unique) -join '/'
                Write-Host ("    {0}  (seen in {1} dumps, codes: {2})" -f $_.Name, $_.Count, $codes) -ForegroundColor Magenta
            }
        }
        if ($sameGroups) {
            Write-Host "  Same-code matches:" -ForegroundColor DarkYellow
            $sameGroups | ForEach-Object { Write-Host ("    {0}  (seen in {1} dumps)" -f $_.Name, $_.Count) -ForegroundColor DarkYellow }
        }
    } else {
        Write-Host "`nNo physical address recurred exactly across more than one dump."
        "PhysicalAddress,MatchType,DumpFile,BugCheckCode,CorruptionType,VirtualAddress,OccurrenceCount" | Out-File -FilePath $corrCsv -Encoding UTF8
    }

    # ----- Near matches, tagged per-pair as SameCode/CrossCode -----
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
            $matchType = if ($a.BugCheckCode -eq $b.BugCheckCode) { "SameCode" } else { "CrossCode" }
            $nearRows += [PSCustomObject]@{
                PhysicalA     = $a.Physical
                DumpA         = $a.Dump
                BugCheckA     = $a.BugCheckCode
                PhysicalB     = $b.Physical
                DumpB         = $b.Dump
                BugCheckB     = $b.BugCheckCode
                DistanceBytes = $dist
                MatchType     = $matchType
            }
        }
    }
    if ($nearRows.Count -gt 0) {
        $nearRows | Sort-Object @{Expression = { if ($_.MatchType -eq "CrossCode") { 0 } else { 1 } }}, DistanceBytes |
            Export-Csv -Path $nearCsv -NoTypeInformation -Encoding UTF8
        Write-Host "`nNear-match candidates (within $ProximityThresholdBytes bytes, different dumps) saved to $nearCsv"

        $crossNear = $nearRows | Where-Object { $_.MatchType -eq "CrossCode" } | Sort-Object DistanceBytes
        $sameNear  = $nearRows | Where-Object { $_.MatchType -eq "SameCode" }  | Sort-Object DistanceBytes

        if ($crossNear) {
            Write-Host "  CROSS-CODE near matches (strongest signal):" -ForegroundColor Magenta
            $crossNear | Select-Object -First 10 | ForEach-Object {
                Write-Host ("    {0} ({1}, {2})  <->  {3} ({4}, {5})   distance 0x{6:X}" -f $_.PhysicalA, $_.DumpA, $_.BugCheckA, $_.PhysicalB, $_.DumpB, $_.BugCheckB, $_.DistanceBytes) -ForegroundColor Magenta
            }
        }
        if ($sameNear) {
            Write-Host "  Same-code near matches:" -ForegroundColor DarkYellow
            $sameNear | Select-Object -First 10 | ForEach-Object {
                Write-Host ("    {0} ({1})  <->  {2} ({3})   distance 0x{4:X}" -f $_.PhysicalA, $_.DumpA, $_.PhysicalB, $_.DumpB, $_.DistanceBytes) -ForegroundColor DarkYellow
            }
        }
    } else {
        Write-Host "`nNo near-match candidates within $ProximityThresholdBytes bytes across different dumps."
        "PhysicalA,DumpA,BugCheckA,PhysicalB,DumpB,BugCheckB,DistanceBytes,MatchType" | Out-File -FilePath $nearCsv -Encoding UTF8
    }

    $typeCsv = Join-Path $OutputFolder "CorruptionType-Summary.csv"
    $results | Select-Object Dump, BugCheckCode, CorruptionType -Unique |
        Sort-Object Dump |
        Export-Csv -Path $typeCsv -NoTypeInformation -Encoding UTF8
    Write-Host "`nPer-dump bugcheck code / P1 summary saved to $typeCsv"
} else {
    Write-Host "No fault-context candidates found in any supported dump."
}

Write-Host "`nDone."