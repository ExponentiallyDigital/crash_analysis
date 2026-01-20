# poolmon_temporal_analysis.ps1
# OPTIMIZED version for large datasets
# Comprehensive temporal analysis of poolmon snapshots

param(
    [string]$LogDir = "C:\PerfLogs\2026-01-19 SECURE_KERNEL_ERROR (18b).DMP\poolmon",
    [string]$OutDir = "C:\PerfLogs\2026-01-19 SECURE_KERNEL_ERROR (18b).DMP",
    [string]$PoolTagFile = "C:\Program Files (x86)\Windows Kits\10\Debuggers\arm64\triage\pooltag.txt",
    [int]$TopN = 50,  # analyse top x tags
    [double]$GrowthThresholdMB = 10
)

# ------------------------------------------------------------
# Load pooltag.txt
# ------------------------------------------------------------
$script:PoolTagLookup = @{}
if (Test-Path $PoolTagFile) {
    Get-Content $PoolTagFile | ForEach-Object {
        $line = $_.Trim()
        if ($line -match '^(//|rem)' -or [string]::IsNullOrWhiteSpace($line)) { return }
        if ($line.Length -lt 4) { return }
        $tag = $line.Substring(0,4)
        $desc = $line.Substring(4).Trim() -replace '^\s*-\s*','' -replace '\s+',' '
        if (-not $script:PoolTagLookup.ContainsKey($tag)) {
            $script:PoolTagLookup[$tag] = $desc
        }
    }
}

# Built-in tag descriptions
$BuiltInTags = @{
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
    "MmSt" = "nt!mm - Section object prototype PTEs, memory manager"
    "MPsc" = "Driver Verifier - Memory Pool Scanner component that tracks pool allocations"
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

function Get-TagDescription($Tag) {
    if ($BuiltInTags.ContainsKey($Tag)) { return $BuiltInTags[$Tag] }
    if ($script:PoolTagLookup.ContainsKey($Tag)) { return $script:PoolTagLookup[$Tag] }
    return "Unknown"
}

# ------------------------------------------------------------
# Parse poolmon file - OPTIMIZED
# ------------------------------------------------------------
function Parse-PoolmonFile($FilePath) {
    $Content = Get-Content $FilePath -ErrorAction SilentlyContinue
    if (-not $Content) { return @() }
    
    $HeaderLine = $Content | Select-String -Pattern "\s*Tag\s+Type" | Select-Object -First 1
    if ($null -eq $HeaderLine) { return @() }
    
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
                    Type   = $Parts[1]
                    Allocs = [long]$Parts[2]
                    Frees  = [long]$Parts[3]
                    Diff   = [long]$Parts[4]
                    Bytes  = [long]$Parts[5]
                }
            } catch {}
        }
    }
    return $Results
}

# ------------------------------------------------------------
# Main analysis
# ------------------------------------------------------------
Write-Host "`n=== POOLMON TEMPORAL ANALYSIS ===" -ForegroundColor Cyan
$Files = Get-ChildItem -Path $LogDir -Filter "*_poolmon_raw.txt" | Sort-Object Name

if ($Files.Count -lt 2) {
    Write-Host "Error: Need at least 2 snapshots" -ForegroundColor Red
    return
}

Write-Host "Found $($Files.Count) snapshots in $LogDir " -ForegroundColor Green

$StartTime = [datetime]::ParseExact($Files[0].BaseName.Substring(0,19), "yyyy-MM-dd_HH-mm-ss", $null)
$EndTime = [datetime]::ParseExact($Files[-1].BaseName.Substring(0,19), "yyyy-MM-dd_HH-mm-ss", $null)
$TotalHours = ($EndTime - $StartTime).TotalHours

Write-Host "Duration: $([math]::Round($TotalHours, 2)) hours`n" -ForegroundColor Gray

# OPTIMIZED: Parse all files and build hash tables directly
Write-Host "Parsing snapshots..." -ForegroundColor Yellow
$TimeSeries = @{}
$SnapshotCount = 0

foreach ($File in $Files) {
    $SnapshotCount++
    if ($SnapshotCount % 10 -eq 0) {
        Write-Host "  Processed $SnapshotCount/$($Files.Count) snapshots..." -ForegroundColor Gray
    }
    
    $Timestamp = [datetime]::ParseExact($File.BaseName.Substring(0,19), "yyyy-MM-dd_HH-mm-ss", $null)
    $Data = Parse-PoolmonFile $File.FullName
    
    foreach ($Entry in $Data) {
        $Key = "$($Entry.Tag)_$($Entry.Type)"
        
        if (-not $TimeSeries.ContainsKey($Key)) {
            $TimeSeries[$Key] = @{
                Tag = $Entry.Tag
                Type = $Entry.Type
                Points = [System.Collections.ArrayList]@()
            }
        }
        
        $null = $TimeSeries[$Key].Points.Add([PSCustomObject]@{
            Timestamp = $Timestamp
            Bytes = $Entry.Bytes
            Allocs = $Entry.Allocs
            Frees = $Entry.Frees
            Diff = $Entry.Diff
        })
    }
}

Write-Host "Built time series for $($TimeSeries.Count) unique Tag+Type combinations`n" -ForegroundColor Green

# ------------------------------------------------------------
# ANALYSIS 1: Monotonic Growth & Basic Stats
# ------------------------------------------------------------
Write-Host "Analyzing growth patterns..." -ForegroundColor Yellow
$Analysis = @()

foreach ($Key in $TimeSeries.Keys) {
    $Series = $TimeSeries[$Key]
    $Points = $Series.Points | Sort-Object Timestamp
    
    if ($Points.Count -lt 2) { continue }
    
    $FirstPoint = $Points[0]
    $LastPoint = $Points[-1]
    
    $GrowthBytes = $LastPoint.Bytes - $FirstPoint.Bytes
    $GrowthMB = $GrowthBytes / 1MB
    
    if ([math]::Abs($GrowthMB) -lt $GrowthThresholdMB) { continue }
    
    # Calculate monotonic percentage
    $MonotonicCount = 0
    for ($i = 1; $i -lt $Points.Count; $i++) {
        $DecreasePercent = if ($Points[$i-1].Bytes -gt 0) { 
            (($Points[$i-1].Bytes - $Points[$i].Bytes) / $Points[$i-1].Bytes) * 100 
        } else { 0 }
        if ($Points[$i].Bytes -ge $Points[$i-1].Bytes -or $DecreasePercent -lt 5) {
            $MonotonicCount++
        }
    }
    $MonotonicPercent = ($MonotonicCount / ($Points.Count - 1)) * 100
    
    # Growth rate
    $HoursElapsed = ($LastPoint.Timestamp - $FirstPoint.Timestamp).TotalHours
    $GrowthRateMBPerHour = if ($HoursElapsed -gt 0) { $GrowthMB / $HoursElapsed } else { 0 }
    
    # Allocation/Free imbalance
    $AllocDelta = $LastPoint.Allocs - $FirstPoint.Allocs
    $FreeDelta = $LastPoint.Frees - $FirstPoint.Frees
    $FreeRatio = if ($AllocDelta -gt 0) { $FreeDelta / $AllocDelta } else { 1 }
    $LeakScore = if ($AllocDelta -gt 0) { $AllocDelta * (1 - $FreeRatio) * ($GrowthMB) } else { 0 }
    
    # Acceleration (first half vs second half)
    $MidPoint = [math]::Floor($Points.Count / 2)
    $FirstHalfGrowth = $Points[$MidPoint-1].Bytes - $Points[0].Bytes
    $SecondHalfGrowth = $Points[-1].Bytes - $Points[$MidPoint].Bytes
    $FirstHalfHours = ($Points[$MidPoint-1].Timestamp - $Points[0].Timestamp).TotalHours
    $SecondHalfHours = ($Points[-1].Timestamp - $Points[$MidPoint].Timestamp).TotalHours
    
    $FirstRate = if ($FirstHalfHours -gt 0) { $FirstHalfGrowth / $FirstHalfHours / 1MB } else { 0 }
    $SecondRate = if ($SecondHalfHours -gt 0) { $SecondHalfGrowth / $SecondHalfHours / 1MB } else { 0 }
    $AccelRatio = if ($FirstRate -gt 0) { $SecondRate / $FirstRate } else { 0 }
    
    # Timing
    $AppearsLate = ($FirstPoint.Timestamp - $StartTime).TotalHours -gt 1
    $DisappearsEarly = ($EndTime - $LastPoint.Timestamp).TotalHours -gt 1
    
    # Current state metrics
    $AvgBytesPerAlloc = if ($LastPoint.Diff -gt 0) { $LastPoint.Bytes / $LastPoint.Diff } else { 0 }
    
    $Analysis += [PSCustomObject]@{
        Tag = $Series.Tag
        Type = $Series.Type
        'Start(MB)' = [math]::Round($FirstPoint.Bytes / 1MB, 2)
        'End(MB)' = [math]::Round($LastPoint.Bytes / 1MB, 2)
        'Growth(MB)' = [math]::Round($GrowthMB, 2)
        'MB/Hour' = [math]::Round($GrowthRateMBPerHour, 3)
        'Monotonic%' = [math]::Round($MonotonicPercent, 0)
        'New Allocs' = $AllocDelta
        'New Frees' = $FreeDelta
        'Free Ratio' = [math]::Round($FreeRatio, 3)
        'Leak Score' = [math]::Round($LeakScore, 0)
        'Early Rate' = [math]::Round($FirstRate, 3)
        'Late Rate' = [math]::Round($SecondRate, 3)
        'Accel Ratio' = [math]::Round($AccelRatio, 2)
        'Diff Count' = $LastPoint.Diff
        'Avg Bytes' = [math]::Round($AvgBytesPerAlloc, 0)
        Snapshots = $Points.Count
        AppearsLate = $AppearsLate
        Disappears = $DisappearsEarly
        Description = Get-TagDescription $Series.Tag
    }
}

Write-Host "Analyzed $($Analysis.Count) tags with significant activity`n" -ForegroundColor Green

# ------------------------------------------------------------
# Paged vs Nonpaged Comparison
# ------------------------------------------------------------
Write-Host "Comparing Paged vs Nonpaged..." -ForegroundColor Yellow
$PagedNonpaged = @()

$Tags = $Analysis | Select-Object -Unique Tag
foreach ($TagObj in $Tags) {
    $Tag = $TagObj.Tag
    $Paged = $Analysis | Where-Object { $_.Tag -eq $Tag -and $_.Type -match '^P' }
    $Nonp = $Analysis | Where-Object { $_.Tag -eq $Tag -and $_.Type -match '^N' }
    
    if ($Paged -and $Nonp) {
        $TotalGrowth = $Paged.'Growth(MB)' + $Nonp.'Growth(MB)'
        if ([math]::Abs($TotalGrowth) -lt $GrowthThresholdMB) { continue }
        
        $NonpPercent = if ($TotalGrowth -ne 0) { ($Nonp.'Growth(MB)' / $TotalGrowth) * 100 } else { 0 }
        
        $PagedNonpaged += [PSCustomObject]@{
            Tag = $Tag
            'Paged(MB)' = $Paged.'Growth(MB)'
            'Nonp(MB)' = $Nonp.'Growth(MB)'
            'Total(MB)' = [math]::Round($TotalGrowth, 2)
            'Nonp%' = [math]::Round($NonpPercent, 0)
            Description = Get-TagDescription $Tag
        }
    }
}

# ------------------------------------------------------------
# Generate Report
# ------------------------------------------------------------
Write-Host "`nGenerating report..." -ForegroundColor Yellow

$Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$ReportFile = Join-Path $OutDir "${Timestamp}_poolmon_analysis.txt"

$Report = @"
================================================================================
POOLMON TEMPORAL ANALYSIS
================================================================================
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Snapshots: $($Files.Count)
Duration: $([math]::Round($TotalHours, 2)) hours
Time Range: $StartTime to $EndTime
Unique Tag+Type: $($TimeSeries.Count)
Analyzed (>$GrowthThresholdMB MB): $($Analysis.Count)

================================================================================
1. TOP GROWTH BY TOTAL BYTES
================================================================================

"@

$Report += $Analysis | 
    Sort-Object 'Growth(MB)' -Descending | 
    Select-Object -First $TopN Tag, Type, 'Start(MB)', 'End(MB)', 'Growth(MB)', 'MB/Hour', Snapshots, Description |
    Format-Table -AutoSize | 
    Out-String

$Report += @"

================================================================================
2. MONOTONIC GROWTH (Steady increase >80%)
================================================================================

"@

$Report += $Analysis | 
    Where-Object { $_.'Monotonic%' -gt 80 } |
    Sort-Object 'Growth(MB)' -Descending | 
    Select-Object -First $TopN Tag, Type, 'Growth(MB)', 'MB/Hour', 'Monotonic%', Description |
    Format-Table -AutoSize | 
    Out-String

$Report += @"

================================================================================
3. ALLOCATION IMBALANCE (Potential Leaks)
================================================================================

"@

$Report += $Analysis | 
    Where-Object { $_.'Leak Score' -gt 100 -or $_.'Free Ratio' -lt 0.8 } |
    Sort-Object 'Leak Score' -Descending | 
    Select-Object -First $TopN Tag, Type, 'New Allocs', 'New Frees', 'Free Ratio', 'Growth(MB)', 'Leak Score', Description |
    Format-Table -AutoSize | 
    Out-String

$Report += @"

================================================================================
4. GROWTH ACCELERATION (Late rate > Early rate)
================================================================================

"@

$Report += $Analysis | 
    Where-Object { $_.'Accel Ratio' -gt 1.5 } |
    Sort-Object 'Accel Ratio' -Descending | 
    Select-Object -First $TopN Tag, Type, 'Early Rate', 'Late Rate', 'Accel Ratio', 'Growth(MB)', Description |
    Format-Table -AutoSize | 
    Out-String

$Report += @"

================================================================================
5. PAGED vs NONPAGED DIVERGENCE
================================================================================

"@

$Report += $PagedNonpaged | 
    Sort-Object 'Total(MB)' -Descending | 
    Select-Object -First $TopN |
    Format-Table -AutoSize | 
    Out-String

$Report += @"

================================================================================
6. HIGH ALLOCATION COUNT / LOW BYTES (Fragmentation)
================================================================================

"@

$Report += $Analysis | 
    Where-Object { $_.'Diff Count' -gt 1000 -and $_.'Avg Bytes' -lt 1024 } |
    Sort-Object 'Diff Count' -Descending | 
    Select-Object -First $TopN Tag, Type, 'Diff Count', 'Avg Bytes', 'End(MB)', Description |
    Format-Table -AutoSize | 
    Out-String

$Report += @"

================================================================================
7. HIGH BYTES / LOW COUNT (Large Buffers)
================================================================================

"@

$Report += $Analysis | 
    Where-Object { $_.'End(MB)' -gt 10 -and $_.'Diff Count' -lt 100 } |
    Sort-Object 'End(MB)' -Descending | 
    Select-Object -First $TopN Tag, Type, 'Diff Count', 'End(MB)', 'Avg Bytes', Description |
    Format-Table -AutoSize | 
    Out-String

$LateTags = $Analysis | Where-Object AppearsLate
$DisappearingTags = $Analysis | Where-Object Disappears

if ($LateTags.Count -gt 0) {
    $Report += @"

================================================================================
8. TAGS APPEARING LATE (After 1 hour)
================================================================================

"@
    $Report += $LateTags | 
        Sort-Object 'Growth(MB)' -Descending |
        Select-Object -First 20 Tag, Type, 'Growth(MB)', Description |
        Format-Table -AutoSize | 
        Out-String
}

if ($DisappearingTags.Count -gt 0) {
    $Report += @"

================================================================================
9. TAGS DISAPPEARING EARLY (Before end)
================================================================================

"@
    $Report += $DisappearingTags | 
        Select-Object -First 20 Tag, Type, 'End(MB)', Description |
        Format-Table -AutoSize | 
        Out-String
}

$Report += "`n================================================================================`n"

$Report | Out-File -FilePath $ReportFile -Encoding UTF8
Write-Host $Report
Write-Host "`nReport saved: $ReportFile" -ForegroundColor Green