<#
.SYNOPSIS
  Extracts candidate corrupted-memory addresses from 0x139
  KERNEL_SECURITY_CHECK_FAILURE dumps by reading the actual fault context
  (trap frame / exception record reported in BUGCHECK_P2 / BUGCHECK_P3),
  rather than scanning every live timer object in the system. Correlates
  resulting physical addresses across multiple dump files.

.NOTES
  This assumes all dumps are 0x139 bugchecks. Dumps with a different
  bugcheck code are skipped, since the fault-context extraction logic
  below (trap frame + exception record from BUGCHECK_P2/P3) is specific
  to 0x139's parameter layout.

  Which register or stack slot actually holds the corrupted structure's
  pointer varies by corruption type (LIST_ENTRY, RBTree node, vtable,
  stack cookie, etc - see BUGCHECK_P1). This script does not try to guess
  which single candidate is "the" one; it collects every kernel-space
  pointer visible in the register set and top of stack at the fault, and
  lets the cross-dump physical-address correlation do the filtering. You
  should sanity-check the exported CSVs, not just trust row 1.

  cdb/dbgeng output formatting can vary slightly by OS build and symbol
  availability. If BUGCHECK_P1/P2/P3 or !pte's "pfn" line don't match on
  your dumps, run one dump manually first and adjust the regexes below to
  match what your cdb version actually prints before trusting the batch.
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

# !pte reliably prints a line containing "pfn <hex>" for the PTE mapping the VA.
# Deliberately no fallback to parsing a "contains <hex>" value as a PFN - that
# field is the raw 64-bit PTE (address + flag bits), not a bare PFN, and using
# it directly as one produces a physical address that isn't real.
function Get-PfnFromPte([string[]]$pteLines) {
    $raw = $pteLines -join "`n"
    if ($raw -match '(?im)^\s*pfn\s+([0-9a-f]+)') { return $Matches[1] }
    return $null
}

function PFN-To-Physical([string]$pfnStr, [string]$va) {
    try {
        $pfn = [Convert]::ToInt64($pfnStr, 16)
        $vaClean = (Get-HexClean $va) -replace '^0x'
        $vaInt = [Convert]::ToInt64($vaClean, 16)
        return "0x{0:X}" -f (($pfn * 0x1000) + ($vaInt -band 0xFFF))
    } catch { return $null }
}

# Is this VA inside a loaded module's *code* range? Resolved dynamically per
# dump via ln, instead of hardcoding a PFN that happened to be kernel code on
# one particular boot. Nonpaged pool / heap addresses generally fall outside
# any module's image range and won't resolve this way.
function Is-LikelyCodePage([string]$dumpPath, [string]$va) {
    $lnLines = Invoke-Cdb -DumpPath $dumpPath -Commands "ln $va"
    $joined = $lnLines -join ' '
    return ($joined -match '(nt!|\.sys!)\S*\+0x[0-9a-f]+')
}

$dumps = Get-ChildItem -Path $DumpFolder -Filter *.dmp | Sort-Object Name
$results = @()

foreach ($dump in $dumps) {
    $dumpPath = $dump.FullName
    Write-Host "`n===== Processing $($dump.Name) =====" -ForegroundColor Yellow

    # --- Bugcheck code + parameters ---
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
        Write-Host "  No usable trap frame address (BUGCHECK_P2 is zero/empty) - skipping fault-context extraction for this dump." -ForegroundColor DarkYellow
        continue
    }

    # --- Restore fault context, then dump registers + top of stack ---
    # .trap on the reported trap frame address restores CPU context at the
    # moment of the fault, so r and dps below reflect the actual failing
    # state rather than the bugcheck handler's own context.
    $trapCmd = if (-not (Is-ZeroOrEmpty $p3)) {
        ".trap 0x$p2; .exr 0x$p3; r; dps @rsp L10"
    } else {
        ".trap 0x$p2; r; dps @rsp L10"
    }
    $ctxLines = Invoke-Cdb -DumpPath $dumpPath -Commands $trapCmd

    # Collect every kernel-space hex value visible in the register set and
    # the first 16 stack slots as a candidate. Broader than "the one true
    # address" on purpose - see NOTES above.
    $candidateVAs = @()
    foreach ($line in $ctxLines) {
        $hexMatches = [regex]::Matches($line, '([0-9a-fA-F`]{12,17})')
        foreach ($m in $hexMatches) {
            $candidate = "0x" + (Get-HexClean $m.Value)
            if ((Is-KernelVA $candidate) -and ($candidateVAs -notcontains $candidate)) {
                $candidateVAs += $candidate
            }
        }
    }

    Write-Host "  Candidate kernel VAs from fault context: $($candidateVAs.Count)"

    foreach ($va in $candidateVAs) {
        $pteLines = Invoke-Cdb -DumpPath $dumpPath -Commands "!pte $va"
        $pfn = Get-PfnFromPte $pteLines
        if (-not $pfn) { continue }

        if (Is-LikelyCodePage $dumpPath $va) { continue }

        $phys = PFN-To-Physical $pfn $va
        if ($phys) {
            $results += [PSCustomObject]@{
                Dump           = $dump.Name
                CorruptionType = $p1
                VA             = $va
                Physical       = $phys
            }
        }
    }
}

# ----- Report -----
Write-Host "`n===== Fault-Context Candidate Physical Addresses ====="
if ($results.Count -gt 0) {
    $results = $results | Sort-Object Physical, Dump

    $allCsv = Join-Path $OutputFolder "FaultContext-Candidates.csv"
    $results | Export-Csv -Path $allCsv -NoTypeInformation -Encoding UTF8
    Write-Host "All candidates saved to $allCsv"

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
        Write-Host "Repeated physical addresses across dumps saved to $corrCsv"
        Write-Host "`n$($physGroups.Count) physical address(es) recurred across multiple dumps:"
        $physGroups | ForEach-Object {
            Write-Host ("  {0}  (seen in {1} dumps)" -f $_.Name, $_.Count)
        }
    } else {
        Write-Host "No physical address recurred across more than one dump."
        "PhysicalAddress,DumpFile,CorruptionType,VirtualAddress,OccurrenceCount" | Out-File -FilePath $corrCsv -Encoding UTF8
    }

    $typeCsv = Join-Path $OutputFolder "CorruptionType-Summary.csv"
    $results | Select-Object Dump, CorruptionType -Unique |
        Sort-Object Dump |
        Export-Csv -Path $typeCsv -NoTypeInformation -Encoding UTF8
    Write-Host "Per-dump corruption type (BUGCHECK_P1) summary saved to $typeCsv"
} else {
    Write-Host "No fault-context candidates found in any 0x139 dump."
}

Write-Host "`nDone."
