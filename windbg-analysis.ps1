# =====================================================
# Batch DMP Analyzer
# =====================================================
# Run this script as Administrator
# =====================================================

# !!!!!!!!!!!!! 
# !!!!!!!!!!!!! edit below line:
# !!!!!!!!!!!!! 
param(
    # Change this to your folder (or pass it on the command line: .\Analyze-Dumps.ps1 -DumpDirectory "C:\path\to\folder")
    [string]$DumpDirectory = "C:\Users\andrew\Desktop"
)

# !!!!!!!!!!!!! 
# !!!!!!!!!!!!! edit below line:
# !!!!!!!!!!!!! 
# Path to cdb.exe (WinDbg console debugger)
$debuggerPath = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe"

# ────────────────────────────────────────────────
# Verify debugger exists
# ────────────────────────────────────────────────
if (-not (Test-Path $debuggerPath)) {
    Write-Host "ERROR: cdb.exe not found at: $debuggerPath" -ForegroundColor Red
    Write-Host "Install Windows SDK Debugging Tools or update the path." -ForegroundColor Yellow
    exit 1
}
Write-Host "cdb.exe found → $debuggerPath" -ForegroundColor Green

# Get all .dmp files in the folder (add -Recurse if you want subfolders too)
$dumpFiles = Get-ChildItem -Path $DumpDirectory -Filter "*.dmp" -File

if ($dumpFiles.Count -eq 0) {
    Write-Host "No .dmp files found in $DumpDirectory" -ForegroundColor Red
    exit
}

Write-Host "Found $($dumpFiles.Count) dump file(s). Starting..." -ForegroundColor Green

foreach ($dumpFile in $dumpFiles) {
    $dumpPath = $dumpFile.FullName
    $txtPath  = [System.IO.Path]::ChangeExtension($dumpPath, ".txt")

    Write-Host "Processing: $($dumpFile.Name)  →  $txtPath" -ForegroundColor Cyan

    # Build commands with extra debug output inside cdb
    # Command block for cdb
$commands = @"
    # open output file
    .logopen "$txtPath"
    .time
    !time
    !sysinfo machineid
    !sysinfo cpuinfo
    !sysinfo cpumicrocode
    !sysinfo cpuspeed
    !sysinfo smbios
    !analyze -v
    !thread
    !vm
    !poolused 0 200
    lmof
    !locks
    !verifier
    !verifier 3
    !fltkd.filters
    !ndiskd.netadapter
    !handle 0 0
    !process 0 0
    !memusage
    .logclose
    q
"@

    # other windbg commands:
    #$commands += "!sysinfo machineid`n" # BIOS version and mobo revision
    #$commands += "!sysinfo cpuinfo`n"  # processor info
    #$commands += "!process <adr> 7"    # show all threads in the crashed process, get address from !analyse eg
                                        # Attached Process ffffe70f73595040 Image: System
    ########
    # Enable below when debugging suspected pool corruption, use‑after‑free, uninitialized memory, overwritten kernel structures,
    # random crashes after hours of uptime or BAD_POOL_HEADER, MEMORY_CORRUPTION, IRQL_NOT_LESS_OR_EQUAL or
    # crashes inside nt!ExFreePool, nt!Mi*, nt!Mm*, etc.
    #
    # Pattern	 Description
    # 0xDEADBEEF - Freed memory/bad memory
    # 0xBAADF00D - Uninitialized local variables (Microsoft debug heap)
    # 0xFEEDF00D - Freed heap memory
    # 0xDEADC0DE - Freed memory marker
    # 0xCCCCCCCC - Uninitialized stack memory (debug builds)
    # 0xCDCDCDCD - Uninitialized heap memory (debug builds)
    # 0xDDDDDDDD - Freed heap memory (debug builds)
    # 0xFDFDFDFD - Guard bytes after heap blocks
    # 0xFEEEFEEE   Freed pool marker (freed memory still in pool)
    # 0xABABABAB - Kernel pool memory after free
    # 0xA5A5A5A5 - Heap slack space
    #
    # NB as X64/86 CPUs use little-endian format, multi-byte values are stored with the least significant byte first,
    # when searching memory for a multi‑byte pattern, you must reverse the byte order.
    # eg. the ASCII bytes for "MZ" are 0x4D 0x5A, but in little‑endian memory they appear as 0x5A4D, so search for 0x5A4D.
    #
    #$commands += "s -d 0 L?0xFFFFFFFFFFFFFFFF 0xDEADBEEF`n"
    #

    # Run cdb and capture any console output / errors
    Write-Host "  Launching cdb..." -NoNewline
    $output = $commands | & $debuggerPath -z "$dumpPath" -c ".logopen nul" 2>&1

    if ($?) {  # Last command succeeded (exit code 0)
        Write-Host " OK" -ForegroundColor Green
    } else {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Host $output -ForegroundColor DarkYellow
    }

    # Check if output file was actually created
    if (Test-Path $txtPath) {
        $size = (Get-Item $txtPath).Length / 1KB
        Write-Host "  → Created: $txtPath  ($([math]::Round($size,1)) KB)" -ForegroundColor Green
    } else {
        Write-Host "  → NO OUTPUT FILE CREATED" -ForegroundColor Red
        Write-Host "  Console output from cdb:" -ForegroundColor Yellow
        Write-Host $output -ForegroundColor DarkYellow
    }
    
    # tiny pause to see script progress
    Start-Sleep -Milliseconds 800
}

Write-Host "Finished processing all files." -ForegroundColor Green