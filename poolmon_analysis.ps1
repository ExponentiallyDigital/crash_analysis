# poolmon_analysis.ps1
$LogDir = "C:\PerfLogs\2026-01-19 SECURE_KERNEL_ERROR (18b).DMP\poolmon"
$outDir = "C:\PerfLogs\2026-01-19 SECURE_KERNEL_ERROR (18b).DMP"
$topx = 9999 # how many poolmon entries to display
$PoolTagFile = "C:\Program Files (x86)\Windows Kits\10\Debuggers\arm64\triage\pooltag.txt"

$Files = Get-ChildItem -Path $LogDir -Filter "*_poolmon_raw.txt" | Sort-Object Name
if ($Files.Count -lt 2) {
    Write-Host "Error: Need at least two snapshots to compare." -ForegroundColor Yellow
    return
}

# ------------------------------------------------------------
# Load pooltag.txt ONCE
# ------------------------------------------------------------
$script:PoolTagLookup = @{}
if (Test-Path $PoolTagFile) {
    Get-Content $PoolTagFile | ForEach-Object {
        $line = $_.Trim()

        # Skip comments and blank lines
        if ($line -match '^(//|rem)' -or [string]::IsNullOrWhiteSpace($line)) { return }

        # Tag = first 4 chars
        if ($line.Length -lt 4) { return }
        $tag = $line.Substring(0,4)

        # Description = everything after the tag
        $desc = $line.Substring(4).Trim()

        # Strip leading "-" and normalise whitespace
        $desc = $desc -replace '^\s*-\s*',''
        $desc = $desc -replace '\s+',' '

        if (-not $script:PoolTagLookup.ContainsKey($tag)) {
            $script:PoolTagLookup[$tag] = $desc
        }
    }
}

# ------------------------------------------------------------
# Tag description lookup
# ------------------------------------------------------------
function Get-TagDescription($Tag) {
    # Built-in known tags
    $descriptions = @{
        "CDmp" = "crashdmp.sys - Crashdump driver"
        "ConT" = "Contiguous physical memory allocations for device drivers"
        "EtwB" = "nt!etw - Etw Buffer"
        "EtwR" = "nt!etw - Etw Registration Event Tracing for Windows (Runtime)"
        "FIcs" = "fileinfo.sys - FileInfo FS-filter Stream Context Information Cache"
        "File" = "File Objects"
        "FMfn" = "fltmgr.sys - NAME_CACHE_NODE structure File Mapping (Fast Mutex)"
        "FMfp" = "fltMgr.sys"
        "FMsl" = "fltmgr.sys - STREAM_LIST_CTRL structure File Mapping (Slow Lock)"
        "MmCa" = "nt!mm - Mm control areas for mapped files Memory Manager Cache"
        "MmPb" = "nt!mm - Paging file bitmaps"
        "MmRe" = "nt!mm - ASLR relocation blocks,  fdc flpydisk mrxsmb20 msfs pnpmem scmbus stream VerifierExt volmgr"
        "MmSt" = "nt!mm - Mm section object prototype ptes Memory Manager Statistics"
        "MPsc" = "Memory Pool Scanner"
        "Ntff" = "ntfs.sys - FCB_DATA NTFS File System"
        "NtxF" = "NT Executive File"
        "NtxI" = "ntfs.sys - FCB_NONPAGED_INDEX NtfsFcbNonpagedIndexLookasideList"
        "NvKP" = "nvlddmkm.sys - nVidia video driver"
        "NvLH" = "nvlddmkm.sys - nVidia video driver"
        "NVRM" = "nvlddmkm.sys - nVidia video driver"
        "Pool" = "Pool tables, etc."
        "RvaL" = "? DolbyAudioProcessing.dll / ntroskrnl / ntkrla57"
        "smBt" = "nt!store or rdyboost.sys - ReadyBoost various B+Tree allocations" 
        "smCB" = "rdyboost.sys"
        "smNp" = "nt!store or rdyboost.sys - ReadyBoost store node pool allocations"
        "Thre" = "nt!ps - Thread objects"
        "Toke" = "nt!se - security token objects"
        "Vepp" = "nt!Vf - Verifier Pool Tracking information"
        "Vi53" = "dxgmms2.sys"
        "Vi54" = "dxgmms2.sys"
        "Vi57" = "dxgmms2.sys"
    }

    # 1. Built-in dictionary wins
    if ($descriptions.ContainsKey($Tag)) {
        return $descriptions[$Tag]
    }

    # 2. Fallback to pooltag.txt lookup
    if ($script:PoolTagLookup.ContainsKey($Tag)) {
        return $script:PoolTagLookup[$Tag]
    }

    # 3. Nothing found
    return "Unknown"
}

# ------------------------------------------------------------
# Parse poolmon raw file
# ------------------------------------------------------------
function ParsePoolmonFile($FilePath) {
    $Content = Get-Content $FilePath
    $HeaderLine = $Content | Select-String -Pattern "\s*Tag\s+Type"
    if ($null -eq $HeaderLine) { return $null }
    
    $StartIndex = $HeaderLine.LineNumber
    $Results = @()
    
    for ($i = $StartIndex; $i -lt $Content.Count; $i++) {
        $Line = $Content[$i].Trim()
        if ([string]::IsNullOrWhiteSpace($Line)) { continue }
        $Parts = $Line -split '\s+'
        if ($Parts.Count -ge 6) {
            try {
                $Results += [PSCustomObject]@{
                    Tag    = $Parts[0]
                    Type   = $Parts[1]  # P / NP / Paged / Nonp etc.
                    Allocs = [long]$Parts[2]
                    Frees  = [long]$Parts[3]
                    Bytes  = [long]$Parts[5]
                }
            } catch {}
        }
    }

    # Group by Tag + Type so Paged and Nonp are distinct
    return $Results |
        Group-Object Tag, Type |
        ForEach-Object {
            $_.Group | Sort-Object Bytes -Descending | Select-Object -First 1
        }
}

# ------------------------------------------------------------
# Perform analysis
# ------------------------------------------------------------
$FirstState = ParsePoolmonFile $Files[0].FullName
$LastState  = ParsePoolmonFile $Files[-1].FullName
$ts = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$summaryFile = Join-Path $outDir "$ts`_poolmon_analysis.txt"

$Comparison = foreach ($LastTag in $LastState) {
    $FirstTag = $FirstState | Where-Object { $_.Tag -eq $LastTag.Tag } | Select-Object -First 1
    $StartBytes = if ($FirstTag) { [long]$FirstTag.Bytes } else { 0 }
    $EndBytes   = [long]$LastTag.Bytes
    $Growth     = $EndBytes - $StartBytes

    [PSCustomObject]@{
        Tag         = $LastTag.Tag
        Type        = $LastTag.Type
        'Start(KB)' = [math]::Round($StartBytes / 1KB, 0)
        'End(KB)'   = [math]::Round($EndBytes / 1KB, 0)
        'Growth(KB)'= [math]::Round($Growth / 1KB, 0)
        NewAllocs   = if ($FirstTag) { $LastTag.Allocs - $FirstTag.Allocs } else { $LastTag.Allocs }
        Description = Get-TagDescription $LastTag.Tag
    }
}

# ------------------------------------------------------------
# Output header + table to screen AND file
# ------------------------------------------------------------
"`n$topx TAGS BY GROWTH (KB):" |
    Tee-Object -FilePath $summaryFile -Append

$Comparison |
    Sort-Object 'Growth(KB)' -Descending |
    Select-Object -First $topx |
    Format-Table -AutoSize |
    Out-String |
    Tee-Object -FilePath $summaryFile -Append

Write-Host "Analysed $($Files.Count) files"
Write-Host "Summary saved to $summaryFile" -ForegroundColor Green
