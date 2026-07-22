<#

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
THIS IS UNVERIFIED WIP CODE, it is broken/does not function correctly, retained only as examples of the approach used
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

.SYNOPSIS
    DDR5 forensic extractor
    Collects crash evidence (PTE, PFN, pool, WHEA, MCA, uptime, SMBIOS, BIOS/AGESA)
    and adds SHA256 hashes + chain-of-custody metadata.

.USAGE
    powershell C:\Users\andrew\Documents\crash_analysis\ddr5_analyser-extract.ps1 -DumpFolder "C:\CrashDumps" -OutputFolder "C:\CrashDumps"

#>

param(
    [Parameter(Mandatory)][string]$DumpFolder,
    [Parameter(Mandatory)][string]$OutputFolder,
    [string]$SymbolPath = "srv*C:\Symbols*https://msdl.microsoft.com/download/symbols",
    [string]$CdbPath   = "cdb.exe"   # allow override, default to PATH
)

New-Item -ItemType Directory -Force -Path $OutputFolder | Out-Null

function Invoke-Cdb {
    param(
        [Parameter(Mandatory)][string]$DumpPath,
        [Parameter(Mandatory)][string]$Commands
    )

    if (-not (Test-Path $DumpPath)) {
        throw "Dump file not found: $DumpPath"
    }

    # Resolve cdb.exe
    $exe = $CdbPath
    if (-not (Test-Path $exe)) {
        # Try PATH resolution
        $resolved = (Get-Command $CdbPath -ErrorAction SilentlyContinue)
        if ($resolved) {
            $exe = $resolved.Source
        } else {
            throw "cdb.exe not found. Set -CdbPath to the full path of cdb.exe or ensure it is in PATH."
        }
    }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $exe

    # Build classic .Arguments string (ArgumentList is null on older PS/.NET)
    # cdb.exe -z <dump> -y <symbols> -c "<commands>; q"
    $escapedDump    = '"' + $DumpPath + '"'
    $escapedSymbols = '"' + $SymbolPath + '"'
    $escapedCmd     = '"' + ($Commands + '; q') + '"'

    $psi.Arguments = "-z $escapedDump -y $escapedSymbols -c $escapedCmd"
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute        = $false
    $psi.CreateNoWindow         = $true

    $proc = [System.Diagnostics.Process]::Start($psi)
    if (-not $proc) {
        throw "Failed to start cdb.exe with arguments: $($psi.Arguments)"
    }

    $out = $proc.StandardOutput.ReadToEnd()
    $err = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()

    if ($proc.ExitCode -ne 0) {
        Write-Warning "cdb.exe exited with code $($proc.ExitCode). stderr:`n$err"
    }

    ($out -split "`r`n|`n") | ForEach-Object { $_.TrimEnd() } | Where-Object { $_ -ne '' }
}

function Is-KernelVA([string]$hex) {
    $clean = $hex.Replace('`','').ToLower()
    return $clean -match '^0xffff[89a-f][0-9a-f]{11}$'
}

$bugCheckMap = @{
    "12B" = "FAULTY_HARDWARE_CORRUPTED_PAGE"
    "7A"  = "KERNEL_DATA_INPAGE_ERROR"
    "164" = "WIN32K_CRITICAL_FAILURE"
}

Get-ChildItem $DumpFolder -Filter *.dmp | ForEach-Object {
    $DumpPath = $_.FullName
    $base = $_.BaseName
    $jsonOut = Join-Path $OutputFolder "$base.json"
    Write-Host "Processing $($_.Name) ..." -ForegroundColor Cyan

    # Symbol handling: use user path if provided, else default
    if ($SymbolPath -ne "srv*C:\Symbols*https://msdl.microsoft.com/download/symbols") {
        $symCmd = ".sympath+ $SymbolPath; .reload /f"
    } else {
        $symCmd = ".symfix; .reload /f"
    }
    $alines = Invoke-Cdb $DumpPath "$symCmd; !analyze -v"
    $aBlock = $alines -join "`n"

    # BugCheck line - multiple patterns
    $bugCheckLine = $null
    foreach ($line in $alines) {
        if ($line -match '^BugCheck\s|^BUGCHECK_CODE:\s|^BugCheckCode\s') {
            $bugCheckLine = $line
            break
        }
    }

    # v10: no "continue" anywhere in this block anymore (see .NOTES item 3).
    # An unparsed dump still gets written, with these fields left empty.
    $bugCheckCode = $null; $bugCheckName = $null; $paramStrings = @()
    if (-not $bugCheckLine) {
        Write-Warning "No BugCheck line in $($_.Name); bugcheck fields will be empty, other data still extracted."
    } elseif ($bugCheckLine -match 'BugCheck\s+([0-9A-Fa-f]+),\s*\{(.*)\}') {
        $bugCheckCode = "0x$($Matches[1])"
        $paramStrings = $Matches[2] -split ',\s*' | ForEach-Object { $_.Trim() }
    } elseif ($bugCheckLine -match '^BUGCHECK_CODE:\s+([0-9A-Fa-f]+)') {
        $bugCheckCode = "0x$($Matches[1])"
        $paramMatch = [regex]::Match($aBlock, 'Arg1: ([0-9a-fA-F`]+).*Arg2: ([0-9a-fA-F`]+).*Arg3: ([0-9a-fA-F`]+).*Arg4: ([0-9a-fA-F`]+)')
        if ($paramMatch.Success) {
            $paramStrings = @(
                $paramMatch.Groups[1].Value,
                $paramMatch.Groups[2].Value,
                $paramMatch.Groups[3].Value,
                $paramMatch.Groups[4].Value
            )
        }
    } else {
        Write-Warning "BugCheck line found but unrecognized format in $($_.Name): $bugCheckLine"
    }

    if ($bugCheckCode) {
        $codeSuffix = $bugCheckCode.Substring(2).ToUpper()
        $bugCheckName = if ($bugCheckMap.ContainsKey($codeSuffix)) {
            $bugCheckMap[$codeSuffix]
        } else {
            $bcNameMatch = [regex]::Match($aBlock, '([A-Z_]+)\s*\(([0-9A-Fa-f]+)\)')
            if ($bcNameMatch.Success -and $bcNameMatch.Groups[2].Value -eq $codeSuffix) {
                $bcNameMatch.Groups[1].Value
            } else { "UNKNOWN" }
        }
    } else {
        $bugCheckName = "UNKNOWN_PARSE_FAILED"
    }

    $params = for ($i=0; $i -lt $paramStrings.Count; $i++) {
        [PSCustomObject]@{
            index       = $i+1
            value       = "0x" + ($paramStrings[$i] -replace '[`'']')
            description = ""
        }
    }

    # Faulting IP
    $faultIPRaw = $null
    $ipCtx = $alines | Select-String "FAULTING_IP:" -SimpleMatch -Context 0,1
    if ($ipCtx -and $ipCtx.Context.PostContext[0] -match '^\s*([0-9a-fA-F`]+)') {
        $faultIPRaw = "0x" + ($Matches[1] -replace '[`'']')
    }

    # Stack
    $stackLines = @()
    if ($aBlock -match '(?s)STACK_TEXT:\s*\n(.*?)(?=\n[A-Z][A-Z_\s]+:|\Z)') {
        $stackLines = $Matches[1].Trim() -split "`n" |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ }
    }

    # Registers
    $regs = @{}
    $regBlock = ($alines | Where-Object { $_ -match '^\s*[a-z0-9]+=' }) -join "`n"
    if ($regBlock) {
        [regex]::Matches($regBlock, '([a-z0-9]+)=([0-9a-fA-F`]+)') | ForEach-Object {
            $regs[$_.Groups[1].Value] = "0x" + ($_.Groups[2].Value -replace '[`'']')
        }
    }

    $processName = if ($aBlock -match 'PROCESS_NAME:\s+(\S+)') { $Matches[1] } else { $null }
    $imageName   = if ($aBlock -match 'IMAGE_NAME:\s+(\S+)')   { $Matches[1] } else { $null }
    $bucketId    = if ($aBlock -match 'DEFAULT_BUCKET_ID:\s+(\S+)') { $Matches[1] } else { $null }
    $timestamp   = if ($aBlock -match 'Debug session time:\s+(.+)') { $Matches[1].Trim() } else { $null }

    $osVersionLine = $alines | Where-Object { $_ -match 'Windows \d+ Kernel' } | Select-Object -First 1
    $osVersion = if ($osVersionLine) { $osVersionLine.Trim() } else { "Unknown" }

    # Collect kernel VAs (always include Arg1)
    $addresses = @()
    if ($faultIPRaw -and (Is-KernelVA $faultIPRaw)) { $addresses += $faultIPRaw }
    if ($params.Count -ge 1) {
        $arg1 = $params[0].value
        if (Is-KernelVA $arg1) { $addresses += $arg1 }
    }
    $regs.Values | Where-Object { Is-KernelVA $_ } | ForEach-Object { $addresses += $_ }
    $params | Where-Object { Is-KernelVA $_.value } | ForEach-Object { $addresses += $_.value }
    foreach ($line in $stackLines) {
        if ($line -match '^([0-9a-fA-F`]+)') {
            $addr = "0x" + ($Matches[1] -replace '[`'']')
            if (Is-KernelVA $addr) { $addresses += $addr }
        }
    }
    $uniqueVAs = $addresses | Select-Object -Unique

    # !pte for each VA (best-effort PFN extraction)
    $pteResults = foreach ($va in $uniqueVAs) {
        $lines = Invoke-Cdb $DumpPath "!pte $va"
        $raw = ($lines -join "`n") -replace '(?m)^0: kd>.*\r?\n?'
        $pfn = $null
        $pfnMatches = [regex]::Matches($raw, '(?i)pfn\s+([0-9a-f]+)')
        if ($pfnMatches.Count -gt 0) {
            $pfn = "0x" + $pfnMatches[$pfnMatches.Count - 1].Groups[1].Value
        } elseif ($raw -match '(?i)contains\s+([0-9a-f]+)') {
            $pfn = "0x$($Matches[1])"
        }
        [PSCustomObject]@{
            VirtualAddress = $va
            RawOutput      = $raw.Trim()
            PFN            = $pfn
        }
    }

    # !address / !pool (best-effort)
    $addrRegions = @{}
    foreach ($va in $uniqueVAs) {
        $alinesAddr = Invoke-Cdb $DumpPath "!address $va"
        $region = ($alinesAddr -join "`n") -replace '(?m)^0: kd>.*\r?\n?'
        $addrRegions[$va] = $region -match 'NonPagedPool|PagedPool'
    }
    $poolResults = foreach ($va in $uniqueVAs) {
        if ($addrRegions[$va]) {
            $lines = Invoke-Cdb $DumpPath "!pool $va"
            $raw = ($lines -join "`n") -replace '(?m)^0: kd>.*\r?\n?'
            [PSCustomObject]@{
                Address   = $va
                RawOutput = $raw.Trim()
                IsPool    = $true
            }
        } else {
            [PSCustomObject]@{
                Address   = $va
                RawOutput = "Not pool region"
                IsPool    = $false
            }
        }
    }

    # Page table bases
    $processDirBase = $userDirBase = $null
    if ($processName) {
        $procLines = Invoke-Cdb $DumpPath "!process 0 0 $processName"
        $procBlock = $procLines -join "`n"
        if ($procBlock -match '(?i)DirBase:\s+([0-9a-fA-F`]+)') {
            $processDirBase = "0x" + ($Matches[1] -replace '[`'']')
        }
        if ($procBlock -match '(?i)UserDirBase:\s+([0-9a-fA-F`]+)') {
            $userDirBase = "0x" + ($Matches[1] -replace '[`'']')
        }
    }
    if (-not $processDirBase) {
        $sysLines = Invoke-Cdb $DumpPath "!process 0 0 System"
        if (($sysLines -join "`n") -match '(?i)DirBase:\s+([0-9a-fA-F`]+)') {
            $processDirBase = "0x" + ($Matches[1] -replace '[`'']')
        }
    }

    # !vtop (best-effort)
    $vaToPhys = foreach ($va in $uniqueVAs) {
        $base = if (Is-KernelVA $va) { $processDirBase } else { $userDirBase }
        if (-not $base) { continue }
        $lines = Invoke-Cdb $DumpPath "!vtop $base $va"
        $raw = $lines -join "`n"
        $physAddr = $null
        if ($raw -match 'Physical Address:\s+([0-9a-fA-F`]+)') {
            $physAddr = "0x" + ($Matches[1] -replace '[`'']')
        } elseif ($raw -match '(?i)translates to physical address\s+([0-9a-fA-F]+)') {
            $physAddr = "0x" + $Matches[1]
        } elseif ($raw -match 'contains\s+([0-9a-f]+)') {
            $pfnVal = "0x$($Matches[1])"
            $offset = [System.Convert]::ToInt64($va, 16) -band 0xFFF
            $physAddr = "0x{0:X}" -f (([System.Convert]::ToInt64($pfnVal, 16) * 0x1000) + $offset)
        }
        $pfn = $null
        $vtopPfnMatches = [regex]::Matches($raw, '(?i)pfn\s+([0-9a-f]+)')
        if ($vtopPfnMatches.Count -gt 0) {
            $pfn = "0x" + $vtopPfnMatches[$vtopPfnMatches.Count - 1].Groups[1].Value
        }
        [PSCustomObject]@{
            VirtualAddress  = $va
            PhysicalAddress = $physAddr
            PFN             = $pfn
            RawVtopOutput   = $raw.Trim()
            Note            = "Physical address identifies the corrupted memory page observed by Windows, NOT the physical DRAM cell or DIMM."
        }
    }

    # Phys dumps (best-effort)
    $physHexDumps = @()
    $seenPhys = @{}
    foreach ($entry in $vaToPhys) {
        if ($entry.PhysicalAddress -and -not $seenPhys.ContainsKey($entry.PhysicalAddress)) {
            $seenPhys[$entry.PhysicalAddress] = $true
            $lines = Invoke-Cdb $DumpPath "!db /p $($entry.PhysicalAddress) L100"
            $raw = ($lines -join "`n") -replace '(?m)^0: kd>.*\r?\n?'
            $physHexDumps += [PSCustomObject]@{
                PhysicalAddress = $entry.PhysicalAddress
                HexDump         = $raw.Trim()
                PFN             = $entry.PFN
                Note            = "Hex dump of the page Windows flagged as corrupted."
            }
        }
    }

    # PFN details
    $uniquePfns = $vaToPhys | Where-Object { $_.PFN } | Select-Object -ExpandProperty PFN -Unique
    $pfnDetails = foreach ($pfn in $uniquePfns) {
        $lines = Invoke-Cdb $DumpPath "!pfn $pfn"
        $raw = ($lines -join "`n") -replace '(?m)^0: kd>.*\r?\n?'
        [PSCustomObject]@{
            PFN       = $pfn
            RawOutput = $raw.Trim()
        }
    }

    # Additional forensic commands (metadata, WHEA, MCA, SMBIOS, uptime)
    $extraCmd = "!whea; !errrec; .time; !sysinfo smbios; !sysinfo machineid; !sysinfo cpuinfo; !sysinfo cpumicrocode; !blackboxmemory; !memmap"
    $extraRaw = (Invoke-Cdb $DumpPath $extraCmd) -join "`n" -replace '(?m)^0: kd>.*\r?\n?'

    # WHEA errors (unlikely on consumer non-ECC)
    $wheaErrors = @()
    $errRecBlocks = [regex]::Split($extraRaw, '(?i)Error record.*?\{') | Where-Object { $_ -match 'Memory Error' }
    foreach ($block in $errRecBlocks) {
        $wheaErrors += [PSCustomObject]@{
            Bank            = if ($block -match 'Bank:\s+(\S+)') { $Matches[1] } else { $null }
            Rank            = if ($block -match 'Rank:\s+(\S+)') { $Matches[1] } else { $null }
            Row             = if ($block -match 'Row:\s+(\S+)')  { $Matches[1] } else { $null }
            Column          = if ($block -match 'Column:\s+(\S+)') { $Matches[1] } else { $null }
            BitPosition     = if ($block -match 'Bit Position:\s+(\S+)') { $Matches[1] } else { $null }
            PhysicalAddress = if ($block -match 'Physical Address:\s+(\S+)') { "0x" + ($Matches[1] -replace '[`'']') } else { $null }
        }
    }

    # MCA registers (likely empty on Ryzen consumer DDR5)
    $mcaEntries = @()
    $lines = $extraRaw -split "`n"
    for ($i=0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match 'MC(\d+)_STATUS:\s+(.+)') {
            $bank   = $Matches[1]
            $status = $Matches[2].Trim()
            $addr   = $null
            if ($i+1 -lt $lines.Count -and $lines[$i+1] -match "MC$bank`_ADDR:\s+([0-9a-fA-F`]+)") {
                $addr = "0x" + ($Matches[1] -replace '[`'']')
            }
            $mcaEntries += [PSCustomObject]@{
                Bank    = $bank
                Status  = $status
                Address = $addr
            }
        }
    }

    # Timer/DPC (contextual)
    $timerDPC = @()
    $relevantBC = @('DPC_WATCHDOG_VIOLATION','CLOCK_WATCHDOG_TIMEOUT','IRQL_NOT_LESS_OR_EQUAL')
    if ($bugCheckName -in $relevantBC) {
        if ($bugCheckName -eq 'DPC_WATCHDOG_VIOLATION' -and $params.Count -ge 3) {
            $dpcRoutine = $params[2].value
            if (Is-KernelVA $dpcRoutine) {
                $lines = Invoke-Cdb $DumpPath "dt nt!_KDPC $dpcRoutine; .echo END_DPC; !timer"
                $timerDPC += [PSCustomObject]@{
                    Type      = "DPC_WATCHDOG"
                    Routine   = $dpcRoutine
                    RawOutput = ($lines -join "`n") -replace '(?m)^0: kd>.*\r?\n?'
                }
            }
        }
        if ($bugCheckName -eq 'CLOCK_WATCHDOG_TIMEOUT') {
            $lines = Invoke-Cdb $DumpPath "!timer"
            $timerDPC += [PSCustomObject]@{
                Type      = "CLOCK_WATCHDOG"
                RawOutput = ($lines -join "`n") -replace '(?m)^0: kd>.*\r?\n?'
            }
        }
        $dpcSum = Invoke-Cdb $DumpPath "!dpcs"
        $timerDPC += [PSCustomObject]@{
            Type      = "DPC_Summary"
            RawOutput = ($dpcSum -join "`n") -replace '(?m)^0: kd>.*\r?\n?'
        }
    }

    # ---- SHA256 hash of dump file ----
    $sha256 = (Get-FileHash -Path $DumpPath -Algorithm SHA256).Hash

    # ---- Forensic chain-of-custody metadata ----
    $extractionTime   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $extractorVersion = "2.1"
    $dumpSizeBytes    = (Get-Item $DumpPath).Length

    # ---- Assemble JSON (depth 100) ----
    $result = [PSCustomObject]@{
        DumpFile  = $_.Name
        SHA256    = $sha256
        Timestamp = $timestamp
        OSVersion = $osVersion
        Analysis  = [PSCustomObject]@{
            BugCheck    = [PSCustomObject]@{
                Code       = $bugCheckCode
                Name       = $bugCheckName
                Parameters = $params
            }
            FaultingIP  = $faultIPRaw
            StackText   = $stackLines
            ProcessName = $processName
            ImageName   = $imageName
            BucketId    = $bucketId
            Registers   = $regs
        }
        Forensics = [PSCustomObject]@{
            PageTable     = $pteResults
            Pool          = $poolResults
            VirtualToPhys = $vaToPhys
            PhysHexDumps  = $physHexDumps
            PFNDetails    = $pfnDetails
            WHEA_Errors   = $wheaErrors
            MCA_Entries   = $mcaEntries
            ExtraRaw      = $extraRaw
            TimerDPC      = $timerDPC
        }
        ExtractionMetadata = [PSCustomObject]@{
            ExtractorVersion = $extractorVersion
            ExtractionUTC    = $extractionTime
            OriginalFileSize = $dumpSizeBytes
        }
    }

    $result | ConvertTo-Json -Depth 100 | Set-Content -Path $jsonOut -Encoding UTF8
    Write-Host "  -> $jsonOut" -ForegroundColor Green
}
