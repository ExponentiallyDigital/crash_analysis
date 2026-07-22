<#
.SYNOPSIS
  For 0x139 crashes, extracts the corrupted object's VA from the trap frame,
  translates it to physical, and reports correlations across dumps.
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
$allCorruptions = @()   # [PSCustomObject]@{ Dump, CorruptedVA, Physical, Type }

foreach ($dump in $dumps) {
    $dumpPath = $dump.FullName
    Write-Host "`n===== Processing $($dump.Name) =====" -ForegroundColor Yellow

    # 1. !analyze -v to get parameters and context
    $analyzeLines = Invoke-Cdb -DumpPath $dumpPath -Commands ".symfix; .reload /f; !analyze -v"

    $bugCheckCode = $null
    $bugCheckP1  = $null  # corruption type
    $bugCheckP2  = $null  # trap frame address
    $bugCheckP3  = $null  # exception record address

    # Extract from BUGCHECK_P1, BUGCHECK_P2, BUGCHECK_P3 lines
    foreach ($line in $analyzeLines) {
        if ($line -match 'BUGCHECK_P1:\s+([0-9a-fA-F`]+)') {
            $bugCheckP1 = "0x" + ($Matches[1] -replace '[^0-9a-fA-F]')
        } elseif ($line -match 'BUGCHECK_P2:\s+([0-9a-fA-F`]+)') {
            $bugCheckP2 = "0x" + ($Matches[1] -replace '[^0-9a-fA-F]')
        } elseif ($line -match 'BUGCHECK_P3:\s+([0-9a-fA-F`]+)') {
            $bugCheckP3 = "0x" + ($Matches[1] -replace '[^0-9a-fA-F]')
        } elseif ($line -match 'BUGCHECK_CODE:\s+([0-9A-Fa-f]+)') {
            $bugCheckCode = "0x$($Matches[1])"
        }
    }

    Write-Host "BugCheck: $bugCheckCode (type $bugCheckP1)"
    if (-not $bugCheckP2 -or -not $bugCheckP3) {
        Write-Warning "Missing trap frame / exception record addresses – cannot extract corrupted object."
        continue
    }

    # 2. Run .trap to get register state
    Write-Host "  Getting trap frame context..."
    $trapLines = Invoke-Cdb -DumpPath $dumpPath -Commands ".trap $bugCheckP2"
    $raw = $trapLines -join "`n"

    # Extract registers from the trap output (typical format: rax=... rbx=... etc.)
    $regs = @{}
    $regMatches = [regex]::Matches($raw, '([a-z0-9]+)=([0-9a-fA-F`]+)')
    foreach ($m in $regMatches) {
        $regs[$m.Groups[1].Value] = "0x" + ($m.Groups[2].Value -replace '[^0-9a-fA-F]')
    }

    # Heuristic: For LIST_ENTRY corruption (type 3), the corrupted list entry is often in rcx or rdx.
    # For other types, we may need to inspect disassembly, but for now we'll use rcx as the most likely.
    $corruptedVA = $null
    if ($bugCheckP1 -eq "0x3") {
        $corruptedVA = $regs['rcx']   # LIST_ENTRY* passed to KiFastFailDispatch
        if (-not (Is-KernelVA $corruptedVA)) { $corruptedVA = $regs['rdx'] }
        if (-not (Is-KernelVA $corruptedVA)) { $corruptedVA = $regs['r8'] }
    } else {
        # Fallback: try rcx, then rdx, then r8
        $corruptedVA = $regs['rcx']
        if (-not (Is-KernelVA $corruptedVA)) { $corruptedVA = $regs['rdx'] }
        if (-not (Is-KernelVA $corruptedVA)) { $corruptedVA = $regs['r8'] }
    }

    if (-not $corruptedVA -or -not (Is-KernelVA $corruptedVA)) {
        Write-Warning "Could not identify a corrupted object address from trap frame registers."
        continue
    }
    Write-Host "  Corrupted object VA: $corruptedVA"

    # 3. Translate via !pte (only explicit pfn extraction)
    Write-Host "  Translating..."
    $pteLines = Invoke-Cdb -DumpPath $dumpPath -Commands "!pte $corruptedVA"
    $pteRaw = $pteLines -join "`n"
    $pfn = $null
    if ($pteRaw -match '(?i)pfn\s+([0-9a-f]+)') {
        $pfn = "0x$($Matches[1])"
    }
    if (-not $pfn) {
        Write-Warning "Could not extract PFN from !pte output."
        continue
    }

    $phys = PFN-To-Physical $pfn $corruptedVA
    if (-not $phys) { continue }

    Write-Host "  -> Physical: $phys (PFN $pfn)"

    $allCorruptions += [PSCustomObject]@{
        Dump         = $dump.Name
        CorruptedVA  = $corruptedVA
        Physical     = $phys
        Type         = $bugCheckP1
    }
}

# ----- Correlate across dumps -----
Write-Host "`n===== Corrupted Object Physical Addresses ====="
if ($allCorruptions.Count -gt 0) {
    $allCorruptions | Sort-Object Physical, Dump | ForEach-Object {
        Write-Host ("{0}: {1} (type {2}) -> {3}" -f $_.Dump, $_.CorruptedVA, $_.Type, $_.Physical)
    }

    # Correlation
    $physGroups = $allCorruptions | Group-Object Physical | Where-Object { $_.Count -gt 1 }
    $corrCsv = Join-Path $OutputFolder "PhysicalAddress-Correlations.csv"
    if ($physGroups) {
        $corrRows = $physGroups | ForEach-Object {
            $phys = $_.Name
            $occ  = $_.Count
            $_.Group | Sort-Object Dump | ForEach-Object {
                [PSCustomObject]@{
                    PhysicalAddress = $phys
                    DumpFile        = $_.Dump
                    CorruptedVA     = $_.CorruptedVA
                    CorruptionType  = $_.Type
                    OccurrenceCount = $occ
                }
            }
        } | Sort-Object PhysicalAddress, DumpFile
        $corrRows | Export-Csv -Path $corrCsv -NoTypeInformation -Encoding UTF8
        Write-Host "`nRepeated corrupted physical addresses saved to $corrCsv"
    } else {
        Write-Host "`nNo physical address repeated across dumps."
        "PhysicalAddress,DumpFile,CorruptedVA,CorruptionType,OccurrenceCount" | Out-File -FilePath $corrCsv -Encoding UTF8
    }
} else {
    Write-Host "No corrupted objects found."
}

Write-Host "`nDone."