<#
.SYNOPSIS
  Extracts kernel VAs from 0x139 crashes (faulting IP + stack),
  translates them to physical addresses, and reports physical
  addresses that appear in multiple dumps.
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

# Helper: strip non-hex characters and prepend 0x
function Clean-Hex([string]$raw) {
    if (-not $raw) { return $null }
    $hex = $raw -replace '[^0-9a-fA-F]'
    if ($hex.Length -eq 0) { return $null }
    return "0x$hex"
}

$dumps = Get-ChildItem -Path $DumpFolder -Filter *.dmp | Sort-Object Name
$allResults = @()

foreach ($dump in $dumps) {
    $dumpPath = $dump.FullName
    $baseName = $dump.BaseName
    Write-Host "Processing $($dump.Name) ..."

    $analyzeLines = Invoke-Cdb -DumpPath $dumpPath -Commands ".symfix; .reload /f; !analyze -v"
    $analyzeLines | Set-Content -Path (Join-Path $OutputFolder "$baseName-analyze.log")

    # BugCheck code
    $bugCheckCode = $null
    $codeLine = $analyzeLines | Where-Object { $_ -match 'BUGCHECK_CODE:\s+([0-9A-Fa-f]+)' }
    if ($codeLine) { $bugCheckCode = "0x$($Matches[1])" }
    else {
        $bcLine = $analyzeLines | Where-Object { $_ -match 'BugCheck\s+([0-9A-Fa-f]+),' }
        if ($bcLine) { $bugCheckCode = "0x$($Matches[1])" }
    }
    Write-Host "  BugCheck: $bugCheckCode"

    # Collect kernel VAs
    $vasToTranslate = [System.Collections.ArrayList]@()

    # 1. Faulting IP – try FAULTING_IP: first, then TRAP_FRAME rip=
    $faultIP = $null
    $ipCtx = $analyzeLines | Select-String "FAULTING_IP:" -SimpleMatch -Context 0,1
    if ($ipCtx -and $ipCtx.Context.PostContext[0] -match '^\s*([0-9a-fA-F`]+)') {
        $faultIP = Clean-Hex $Matches[1]
    }
    if (-not $faultIP) {
        foreach ($line in $analyzeLines) {
            if ($line -match 'rip=([0-9a-fA-F`]+)') {
                $faultIP = Clean-Hex $Matches[1]
                break
            }
        }
    }
    if ($faultIP -and (Is-KernelVA $faultIP)) {
        $vasToTranslate.Add($faultIP) | Out-Null
        Write-Host "  FaultIP: $faultIP"
    }

    # 2. Stack return addresses (up to 5 unique kernel VAs)
    $inStack = $false
    $stackLines = @()
    foreach ($line in $analyzeLines) {
        if ($line -match '^STACK_TEXT:') { $inStack = $true; continue }
        if ($inStack -and $line -match '^[A-Z_]+:') { break }
        if ($inStack) { $stackLines += $line }
    }
    $stackCount = 0
    foreach ($sl in $stackLines) {
        if ($stackCount -ge 5) { break }
        $hexMatches = [regex]::Matches($sl, '([0-9a-fA-F`]{12,17})')
        foreach ($m in $hexMatches) {
            if ($stackCount -ge 5) { break }
            $candidate = Clean-Hex $m.Value
            if (Is-KernelVA $candidate -and ($vasToTranslate -notcontains $candidate)) {
                $vasToTranslate.Add($candidate) | Out-Null
                $stackCount++
                Write-Host "  Stack addr: $candidate"
            }
        }
    }

    if ($vasToTranslate.Count -eq 0) {
        Write-Warning "No kernel VAs to translate for $baseName"
        $allResults += [PSCustomObject]@{ DumpFile=$dump.Name; BugCheckCode=$bugCheckCode; Translations=@() }
        continue
    }

    # Kernel page table base
    $kernelDirBase = $null
    $sysLines = Invoke-Cdb -DumpPath $dumpPath -Commands "!process 0 0 System"
    if (($sysLines -join "`n") -match 'DirBase:\s+([0-9a-fA-F`]+)') {
        $kernelDirBase = Clean-Hex $Matches[1]
    }
    if (-not $kernelDirBase) {
        $cr3Lines = Invoke-Cdb -DumpPath $dumpPath -Commands "r cr3"
        if (($cr3Lines -join "`n") -match 'cr3=([0-9a-fA-F`]+)') {
            $kernelDirBase = Clean-Hex $Matches[1]
        }
    }
    if (-not $kernelDirBase) {
        Write-Warning "No kernel page table base for $baseName"
        continue
    }
    Write-Host "  DirBase: $kernelDirBase"

    # Translate
    $translations = @()
    foreach ($va in $vasToTranslate) {
        $vtopLines = Invoke-Cdb -DumpPath $dumpPath -Commands "!vtop $kernelDirBase $va"
        $raw = $vtopLines -join "`n"
        $physAddr = $null
        if ($raw -match 'Physical Address:\s+([0-9a-fA-F`]+)') {
            $physAddr = Clean-Hex $Matches[1]
        } elseif ($raw -match 'contains\s+([0-9a-f]+)') {
            $pfnVal = "0x$($Matches[1])"
            $offset = [Convert]::ToInt64($va, 16) -band 0xFFF
            $physAddr = "0x{0:X}" -f (([Convert]::ToInt64($pfnVal, 16) * 0x1000) + $offset)
        }
        $pfn = if ($raw -match '(?i)pfn\s+([0-9a-f]+)') { "0x$($Matches[1])" } else { $null }
        Write-Host "    $va -> Physical: $physAddr (PFN: $pfn)"
        $translations += [PSCustomObject]@{ VirtualAddress=$va; PFN=$pfn; PhysicalAddress=$physAddr }
    }

    $allResults += [PSCustomObject]@{
        DumpFile=$dump.Name
        BugCheckCode=$bugCheckCode
        Translations=$translations
    }
}

# Correlation
Write-Host "`nPhysical addresses found:"
$physMap = @{}
foreach ($r in $allResults) {
    foreach ($t in $r.Translations) {
        if ($t.PhysicalAddress) {
            $key = $t.PhysicalAddress
            if (-not $physMap.ContainsKey($key)) { $physMap[$key] = @() }
            $physMap[$key] += [PSCustomObject]@{ Dump=$r.DumpFile; VA=$t.VirtualAddress }
        }
    }
}
foreach ($entry in $physMap.GetEnumerator() | Sort-Object { $_.Value.Count } -Descending) {
    Write-Host ("{0} ({1} occurrences):" -f $entry.Key, $entry.Value.Count)
    foreach ($v in $entry.Value) { Write-Host "    $($v.Dump) -> VA $($v.VA)" }
}

# Export
$corrCsv = Join-Path $OutputFolder "PhysicalAddress-Correlations.csv"
$correlations = $physMap.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 }
if ($correlations) {
    $rows = $correlations | ForEach-Object {
        $addr = $_.Key
        $_.Value | ForEach-Object {
            [PSCustomObject]@{ PhysicalAddress=$addr; DumpFile=$_.Dump; VirtualAddress=$_.VA; OccurrenceCount=$_.Value.Count }
        }
    }
    $rows | Export-Csv -Path $corrCsv -NoTypeInformation -Encoding UTF8
    Write-Host "Correlation CSV saved to $corrCsv"
} else {
    Write-Host "No physical address appeared in more than one dump."
    "PhysicalAddress,DumpFile,VirtualAddress,OccurrenceCount" | Out-File -FilePath $corrCsv -Encoding UTF8
}

Write-Host "Done."