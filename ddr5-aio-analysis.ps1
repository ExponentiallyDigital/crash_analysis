<#
.SYNOPSIS
  Extracts candidate corrupted-memory addresses from these dump types and
  correlates the resulting physical addresses - both exact matches and near
  misses - across multiple dump files:

   KERNEL_SECURITY_CHECK_FAILURE (0x139)
   SYSTEM_SERVICE_EXCEPTION (0x3b)
   SYSTEM_THREAD_EXCEPTION_NOT_HANDLED (0x7e)
   MEMORY_MANAGEMENT (0x1a)
   CRITICAL_PROCESS_DIED (ef)

  Does not yet cater for:

   IRQL_NOT_LESS_OR_EQUAL (a) - 10 historical incidences
   SECURE_KERNEL_ERROR (18b) - 5 historical incidences

  
.NOTES
v0.1.8 Fix ($ExceptionBasedBugChecks -contains $bugCheckCode) for 0xef
v0.1.7 Added CRITICAL_PROCESS_DIED (ef) analysis (same processing as 0x1a)
v0.1.6 Added 0x1a, which does not fit the other three codes' pattern:

  0x139/0x3b/0x7e all reach KeBugCheckEx via an exception, so !analyze -v
  always prints a TRAP_FRAME:/CONTEXT: register block and P2-P4 are always
  debugger bookkeeping addresses (trap frame / exception record / context
  record) - safe to exclude uniformly, as v6 does.

  0x1a is raised directly by the memory manager when it detects corruption,
  with no exception involved, so there is usually no TRAP_FRAME:/CONTEXT:
  block at all. Worse, per Microsoft's own documentation "any other values
  for parameter 1 must be individually examined" - Arg1 selects a subtype,
  and Arg2-Arg4's meaning is entirely different per subtype (an address in
  some cases, a count in others). Blanket-excluding P2-P4 the way v6 does
  for the other codes would be wrong here, since for some subtypes Arg2 IS
  the payload, not bookkeeping.

  This script only special-cases the one subtype in the request (Arg1 =
  0x41790, "a page table page has been corrupted"), where Arg2 is
  documented as the address of the PFN-database entry for the corrupted
  page table page (64-bit OS semantics only - this pipeline assumes x64
  throughout anyway). That address is added as a real candidate rather
  than excluded, and is tagged with a Note explaining an important caveat:
  its !pte-derived physical address is the PFN database entry's own
  backing page, not the corrupted page table page itself - useful as a
  correlation fingerprint, not as the fault location directly.

  For any other 0x1a Arg1 value, Arg2-Arg4 are NOT auto-added as
  candidates, since their meaning is unverified for that subtype. A
  console warning names the subtype and says it needs manual checking
  against Microsoft's bugcheck reference before extending this script to
  cover it.
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

$SupportedBugChecks = @("0x139", "0x3b", "0x7e", "0x1a", "0xef")
$ExceptionBasedBugChecks = @("0x139", "0x3b", "0x7e")

# Known, verified 0x1a Arg1 subtypes. Key is the lowercased, zero-stripped
# hex value of Arg1. Extend only after checking Microsoft's bugcheck
# reference for the subtype's actual Arg2-Arg4 semantics.
$KnownMemoryManagementSubtypes = @{
    "41790" = "A page table page has been corrupted. Arg2 is the address of the PFN-database entry for the corrupted page table page (64-bit OS)."
}

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

# Same as Hex-ToInt64 but returns $null instead of throwing.
function Try-HexToInt64([string]$hex) {
    if (Is-ZeroOrEmpty $hex) { return $null }
    try { return Hex-ToInt64 $hex } catch { return $null }
}

# Lowercased, zero-stripped hex string - used as a lookup key for the
# 0x1a subtype table, since BUGCHECK_P1 is printed without padding.
function Normalize-HexForLookup([string]$hex) {
    if (-not $hex) { return "" }
    $clean = ((Get-HexClean $hex) -replace '^0x').ToLower().TrimStart('0')
    if ($clean -eq "") { return "0" }
    return $clean
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

# Broad scan using the strict 16-digit hex token pattern.
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

    # Bookkeeping-address exclusion is code-dependent. For 0x139/0x3b/0x7e,
    # P2-P4 are always debugger self-reference addresses (trap frame /
    # exception record / context record) and are safe to exclude uniformly.
    # For 0x1a, Arg2-P4's meaning depends entirely on the Arg1 subtype - see
    # NOTES above - so only P1 (the subtype code itself) is excluded here;
    # anything else is handled explicitly per known subtype below.
    if ($ExceptionBasedBugChecks -contains $bugCheckCode) {
        $excludedInts = @($p1, $p2, $p3, $p4) | ForEach-Object { Try-HexToInt64 $_ } | Where-Object { $null -ne $_ }
    } elseif ($bugCheckCode -eq "0x1a") {
        $excludedInts = @($p1) | ForEach-Object { Try-HexToInt64 $_ } | Where-Object { $null -ne $_ }
    } else {
        $excludedInts = @()
    }

    $lmResult = Invoke-Cdb -DumpPath $dumpPath -Commands "lm"
    if ($lmResult.TimedOut) {
        Write-Host "  Note: lm timed out - module-range filtering will use whatever partial list was captured." -ForegroundColor DarkYellow
    }
    $moduleRanges = Get-ModuleRangesFromLines $lmResult.Lines
    Write-Host "  Loaded module ranges captured: $($moduleRanges.Count)"

    # Register block header: "TRAP_FRAME:" for 0x139 (.trap), "CONTEXT:" for
    # 0x3b/0x7e (.cxr). 0x1a is usually raised directly by the memory
    # manager with no exception, so this block is often absent for it -
    # that's expected, not an error.
    $regBlockLines = Get-Section -lines $analyzeLines -startPattern '^(TRAP_FRAME|CONTEXT):' -stopPatterns @('^Resetting default scope', '^EXCEPTION_RECORD:', '^BLACKBOX') -maxLines 12
    $stackTextLines = Get-Section -lines $analyzeLines -startPattern '^STACK_TEXT:' -stopPatterns @('^STACK_COMMAND:') -maxLines 40

    if ($regBlockLines.Count -eq 0) {
        if ($bugCheckCode -eq "0x1a" -or $bugCheckCode -eq "0xef") {
            Write-Host "  No TRAP_FRAME/CONTEXT block (expected for most 0x1a subtypes, which aren't exception-based). Continuing with STACK_TEXT and subtype-specific arguments." -ForegroundColor DarkGray
        } else {
            Write-Host "  No TRAP_FRAME/CONTEXT register block found in !analyze -v output - skipping this dump." -ForegroundColor DarkYellow
            continue
        }
    }

    $rspValue = $null
    foreach ($l in $regBlockLines) {
        if ($l -match 'rsp=([0-9a-f]+)') { $rspValue = $Matches[1]; break }
    }

    $candidateVAs = Get-CandidatesFromLines ($regBlockLines + $stackTextLines) $HexTokenPattern

    # Best-effort deeper stack read (only fires if a register block gave us
    # an rsp - won't apply to most 0x1a dumps, which is fine).
    if ($rspValue -and -not (Is-ZeroOrEmpty $rspValue)) {
        $dpsResult = Invoke-Cdb -DumpPath $dumpPath -Commands "dps 0x$rspValue L16" -TimeoutSeconds 30
        if ($dpsResult.TimedOut) {
            Write-Host "  Note: supplementary stack dps timed out - continuing without it." -ForegroundColor DarkYellow
        }
        $extra = Get-CandidatesFromDpsLines $dpsResult.Lines $HexTokenCore
        foreach ($c in $extra) { if ($candidateVAs -notcontains $c) { $candidateVAs += $c } }
    }

    # Per-candidate notes, for cases where a candidate's meaning needs
    # explanation beyond "found in a register/stack slot".
    $candidateNotes = @{}

    if ($bugCheckCode -eq "0x1a") {
        $subtype = Normalize-HexForLookup $p1
        if ($KnownMemoryManagementSubtypes.ContainsKey($subtype)) {
            Write-Host "  0x1a subtype $p1 recognized: $($KnownMemoryManagementSubtypes[$subtype])" -ForegroundColor Cyan
            if ($subtype -eq "41790") {
                $p2Candidate = "0x" + (Get-HexClean $p2)
                if ((Is-KernelVA $p2Candidate) -and ($candidateVAs -notcontains $p2Candidate)) {
                    $candidateVAs += $p2Candidate
                    $candidateNotes[$p2Candidate] = "Arg2 for 0x1a subtype 0x41790: address of the PFN-database entry for the corrupted page table page. The physical address below is that PFN entry's own backing page, not the corrupted page table page itself - useful for correlation, not as the fault location directly."
                }
            }
        } else {
            Write-Host "  0x1a subtype $p1 is not a recognized/verified subtype in this script. Per Microsoft's bugcheck reference, Arg2-Arg4 meaning differs per subtype and must be checked manually before treating them as addresses - they are NOT auto-added as candidates here." -ForegroundColor DarkYellow
        }
    }

    if ($bugCheckCode -eq "0xef") {
        foreach ($v in @($p1, $p3)) {
            $c = "0x" + (Get-HexClean $v)
            if ((Is-KernelVA $c) -and ($candidateVAs -notcontains $c)) {
                $candidateVAs += $c
                $candidateNotes[$c] = "0xef Arg1/Arg3: process/thread object involved in critical process death (not debugger bookkeeping)."
            }
        }
    }

    $preExclusionCount = $candidateVAs.Count
    $candidateVAs = $candidateVAs | Where-Object { $excludedInts -notcontains (Hex-ToInt64 $_) }
    $excludedCount = $preExclusionCount - $candidateVAs.Count
    if ($excludedCount -gt 0) {
        Write-Host "  Excluded $excludedCount candidate(s) matching known bookkeeping values." -ForegroundColor DarkGray
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
            $note = ""
            if ($candidateNotes.ContainsKey($va)) { $note = $candidateNotes[$va] }
            $results += [PSCustomObject]@{
                Dump           = $dump.Name
                BugCheckCode   = $bugCheckCode
                CorruptionType = $p1
                VA             = $va
                Physical       = $phys
                PhysicalInt    = Hex-ToInt64 $phys
                Note           = $note
            }
        }
    }
}

Write-Host "`n===== Fault-Context Candidate Physical Addresses ====="
if ($results.Count -gt 0) {
    $results = $results | Sort-Object Physical, Dump

    $allCsv = Join-Path $OutputFolder "FaultContext-Candidates.csv"
    $results | Select-Object Dump, BugCheckCode, CorruptionType, VA, Physical, Note |
        Export-Csv -Path $allCsv -NoTypeInformation -Encoding UTF8
    Write-Host "All candidates (post module-range + bookkeeping filtering) saved to $allCsv"

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
                    Note            = $_.Note
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
        "PhysicalAddress,MatchType,DumpFile,BugCheckCode,CorruptionType,VirtualAddress,OccurrenceCount,Note" | Out-File -FilePath $corrCsv -Encoding UTF8
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
