<#
.SYNOPSIS
  Physical address correlation targeting the actual corrupted data
  (timer LIST_ENTRY) for 0x139 crashes, plus crash-code-path context.
  Limits stack VAs to 8 and clearly labels them on-screen.
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
$allTranslations = @()

foreach ($dump in $dumps) {
    $dumpPath = $dump.FullName
    $baseName = $dump.BaseName
    Write-Host "`n===== Processing $($dump.Name) =====" -ForegroundColor Yellow

    # ----- 1. !analyze -v for bugcheck info -----
    $analyzeLines = Invoke-Cdb -DumpPath $dumpPath -Commands ".symfix; .reload /f; !analyze -v"

    $bugCheckCode = $null
    $codeLine = $analyzeLines | Where-Object { $_ -match 'BUGCHECK_CODE:\s+([0-9A-Fa-f]+)' }
    if ($codeLine) { $bugCheckCode = "0x$($Matches[1])" }
    Write-Host "BugCheck: $bugCheckCode"

    # ----- 2. !timer to find potentially corrupted KTIMER structures -----
    Write-Host "  Searching timer list for corruption clues..."
    $timerLines = Invoke-Cdb -DumpPath $dumpPath -Commands "!timer"
    # Look for timer addresses (kernel VAs) in the !timer output
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
    # Take up to 5 timer VAs (avoid flooding)
    $timerVAs = $timerVAs | Select-Object -First 5
    Write-Host "  Timer VAs to translate: $($timerVAs.Count)"

    # ----- 3. Stack addresses (limit 8, clearly flagged) -----
    Write-Host "  Extracting up to 8 unique stack VAs (crash code path)..."
    $stackVAs = [System.Collections.ArrayList]@()

    $faultIP = $null
    $ripMatch = $analyzeLines | Where-Object { $_ -match 'rip=([0-9a-fA-F`]+)' } | Select-Object -First 1
    if ($ripMatch) {
        $faultIP = "0x" + ($Matches[1] -replace '[^0-9a-fA-F]')
        if (Is-KernelVA $faultIP -and $stackVAs -notcontains $faultIP) {
            $stackVAs.Add($faultIP) | Out-Null
            Write-Host "    Stack VA 1 (faulting IP): $faultIP"
        }
    }

    $inStack = $false
    foreach ($line in $analyzeLines) {
        if ($line -match '^STACK_TEXT:') { $inStack = $true; continue }
        if ($inStack -and $line -match '^[A-Z_]+:') { break }
        if ($inStack) {
            $hexMatches = [regex]::Matches($line, '([0-9a-fA-F`]{12,17})')
            foreach ($m in $hexMatches) {
                if ($stackVAs.Count -ge 8) { break }
                $candidate = "0x" + ($m.Value -replace '[^0-9a-fA-F]')
                if (Is-KernelVA $candidate -and $stackVAs -notcontains $candidate) {
                    $stackVAs.Add($candidate) | Out-Null
                    Write-Host "    Stack VA $($stackVAs.Count): $candidate"
                }
            }
        }
        if ($stackVAs.Count -ge 8) { break }
    }
    Write-Host "  (Stack VA collection capped at 8 to avoid excessive duplicates)"

    # ----- 4. Translate timer VAs (potential corruption targets) -----
    Write-Host "`n  -- Timer objects (potential corruption targets) --"
    foreach ($va in $timerVAs) {
        $pteLines = Invoke-Cdb -DumpPath $dumpPath -Commands "!pte $va"
        $raw = $pteLines -join "`n"
        $pfn = $null
        if ($raw -match '(?i)pfn\s+([0-9a-f]+)') { $pfn = "0x$($Matches[1])" }
        elseif ($raw -match '(?i)contains\s+([0-9a-f]+)') { $pfn = "0x$($Matches[1])" }
        $phys = if ($pfn) { PFN-To-Physical $pfn $va } else { $null }
        if ($phys) {
            $allTranslations += [PSCustomObject]@{ Dump = $dump.Name; VA = $va; Physical = $phys; Source = "TIMER" }
            Write-Host "    $va -> $phys  [TIMER]"
        }
    }

    # ----- 5. Translate stack VAs (crash code path – not corrupted data) -----
    Write-Host "`n  -- Crash code path addresses (not corrupted data) --"
    foreach ($va in $stackVAs) {
        $pteLines = Invoke-Cdb -DumpPath $dumpPath -Commands "!pte $va"
        $raw = $pteLines -join "`n"
        $pfn = $null
        if ($raw -match '(?i)pfn\s+([0-9a-f]+)') { $pfn = "0x$($Matches[1])" }
        elseif ($raw -match '(?i)contains\s+([0-9a-f]+)') { $pfn = "0x$($Matches[1])" }
        $phys = if ($pfn) { PFN-To-Physical $pfn $va } else { $null }
        if ($phys) {
            $allTranslations += [PSCustomObject]@{ Dump = $dump.Name; VA = $va; Physical = $phys; Source = "STACK" }
            Write-Host "    $va -> $phys  [STACK]"
        }
    }
}

# ----- Sorted display -----
Write-Host "`n===== All Physical Addresses (sorted) ====="
$allTranslations = $allTranslations | Sort-Object Physical, Dump
$allTranslations | ForEach-Object {
    Write-Host ("{0}: {1} -> {2}  [{3}]" -f $_.Dump, $_.VA, $_.Physical, $_.Source)
}

# ----- Correlation (physical addresses in multiple dumps) -----
$physGroups = $allTranslations | Group-Object Physical | Where-Object { $_.Count -gt 1 }
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
                Source          = $_.Source
                OccurrenceCount = $occ
            }
        }
    } | Sort-Object PhysicalAddress, DumpFile
    $corrRows | Export-Csv -Path $corrCsv -NoTypeInformation -Encoding UTF8
    Write-Host "`nRepeated physical addresses saved to $corrCsv"

    # Highlight which are TIMER vs STACK
    $timerRepeats = $corrRows | Where-Object { $_.Source -eq "TIMER" }
    $stackRepeats = $corrRows | Where-Object { $_.Source -eq "STACK" }
    if ($timerRepeats) {
        Write-Host "`n*** TIMER object repeats (these may indicate the corrupted data location):"
        $timerRepeats | ForEach-Object { Write-Host "  $($_.PhysicalAddress) - $($_.DumpFile)" }
    }
    if ($stackRepeats) {
        Write-Host "`n    Stack code-path repeats (these are the crash mechanism, not corrupted RAM):"
        $stackRepeats | ForEach-Object { Write-Host "  $($_.PhysicalAddress) - $($_.DumpFile)" }
    }
} else {
    "PhysicalAddress,DumpFile,VirtualAddress,Source,OccurrenceCount" | Out-File -FilePath $corrCsv -Encoding UTF8
    Write-Host "`nNo physical address appeared in more than one dump."
}

Write-Host "`nDone."