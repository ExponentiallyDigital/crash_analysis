# =====================================================
# Batch DMP Analyzer (DDR5 Edition)
# =====================================================
# Usage:
#   .\Analyze-DDR5.ps1 -DumpDirectory "C:\CrashDumps"
# =====================================================

param(
    # Change this to your folder or pass it on the command line
    [string]$DumpDirectory = "C:\CrashDumps"
)

# Path to cdb.exe (WinDbg console debugger)
$debuggerPath = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe"

# ────────────────────────────────────────────────
# Verify debugger exists
# ────────────────────────────────────────────────
if (-not (Test-Path $debuggerPath)) {
    Write-Host "ERROR: cdb.exe not found at: $debuggerPath" -ForegroundColor Red
    exit 1
}

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

    # We inject the dynamic output filename at the top
    $commands = ".logopen `"$txtPath`"`n"
    
    # We use a single-quoted string block (@' ... '@) for the rest so PowerShell 
    # doesn't accidentally evaluate your $t0/$t1 pseudo-registers or $$ symbols.
    $commands += @'
$$ ==========================================================================================================
$$ DDR5 refresh defect advanced forensic memory dump extraction
$$ ==========================================================================================================

.block { .symfix; .reload }

$$ ============================================================
$$ SECTION 1: METADATA
$$ ============================================================
.echo ###SECTION:METADATA###
!sysinfo machineid
!sysinfo cpuspeed

$$ ============================================================
$$ SECTION 2: BUGCHECK
$$ ============================================================
.echo ###SECTION:BUGCHECK###
!analyze -v
r $t0 = @$bugcheck
r $t1 = @$bugcheckparam1
r $t2 = @$bugcheckparam2
r $t3 = @$bugcheckparam3
r $t4 = @$bugcheckparam4
.echo BUGCHECK_CODE = 0x${$t0}
.echo BUGCHECK_P1 = ${$t1}
.echo BUGCHECK_P2 = ${$t2}
.echo BUGCHECK_P3 = ${$t3}
.echo BUGCHECK_P4 = ${$t4}

$$ ============================================================
$$ SECTION 3: CORRUPTION VA & PTE RESOLUTION
$$ ============================================================
.echo ###SECTION:CORRUPTION###
r $t5 = @$bugcheckparam1

$$ Smart Address Safeguard: If param1 is a subcode/error code instead of a VA, 
$$ redirect the scanner to the true exception address or faulting instruction pointer.
.if (${$t5} < 0x1000)
{
    r $t5 = @$exaddress
    .if (${$t5} < 0x1000) { r $t5 = @$ip }
}

.echo CORRUPTED_VA = ${$t5}

.if (@$ptrsize == 8)
{
    .if (${$t5} >= 0xffff000000000000) { .echo VA_TYPE = KERNEL }
    .elsif (${$t5} < 0x00007fff00000000) { .echo VA_TYPE = USER }
    .else { .echo VA_TYPE = OTHER }
}

$$ Full PTE walk - dumps all 4 levels
!pte ${$t5}

$$ Try to extract PTE entry values manually for cleaner parsing
$$ This reads the PTE entry itself
r $t6 = ${$t5}
!pte ${$t6}

$$ ============================================================
$$ SECTION 4: PFN DEEP DIVE
$$ ============================================================
.echo ###SECTION:PFN###
$$ We need to extract PFN from !pte output. Try !vtop as alternative.
.process
!vtop 0 ${$t5}

$$ Also dump PFN database entry if we can infer PFN
$$ The !pte output will show "pfn XXXXX" which we parse in Python

$$ ============================================================
$$ SECTION 5: FULL CONTENT DUMP (4KB page)
$$ ============================================================
.echo ###SECTION:CONTENT###
.echo DUMP_START_VA = ${$t5}
$$ 4KB in qwords = 512 entries. Dump first 64 for speed, full page if needed.
dq ${$t5} L64
db ${$t5} L100

$$ ============================================================
$$ SECTION 6: ADJACENT ROW GHOST HUNTING
$$ ============================================================
.echo ###SECTION:ADJACENT###
$$ DDR5 row sizes: 1KB (0x400), 2KB (0x800). Check multiples.
.echo ADJACENT_MINUS_800
dq ${$t5}-0x800 L16
.echo ADJACENT_MINUS_400
dq ${$t5}-0x400 L16
.echo ADJACENT_PLUS_400
dq ${$t5}+0x400 L16
.echo ADJACENT_PLUS_800
dq ${$t5}+0x800 L16
.echo ADJACENT_PLUS_1000
dq ${$t5}+0x1000 L16
.echo ADJACENT_PLUS_2000
dq ${$t5}+0x2000 L16
.echo ADJACENT_PLUS_4000
dq ${$t5}+0x4000 L16

$$ ============================================================
$$ SECTION 7: POOL HEADER FORENSICS
$$ ============================================================
.echo ###SECTION:POOL###
!pool ${$t5}
!address ${$t5}

$$ Try to dump POOL_HEADER if this is pool memory
$$ POOL_HEADER is 16 bytes before allocation start for x64
$$ !pool tells us the allocation base; we dump header there

$$ ============================================================
$$ SECTION 8: OBJECT VALIDATION
$$ ============================================================
.echo ###SECTION:OBJECT###
$$ Only works if VA is a kernel object. Wrap in try/catch equivalent.
.foreach /pS 1 (obj { !object ${$t5} }) { .echo OBJECT_INFO = obj }

$$ ============================================================
$$ SECTION 9: CALL STACK & CONTEXT
$$ ============================================================
.echo ###SECTION:STACK###
kL

.echo ###SECTION:REGISTERS###
r

$$ ============================================================
$$ SECTION 10: TIMER & DPC STATE
$$ ============================================================
.echo ###SECTION:TIMERS###
!timer

.echo ###SECTION:DPC###
!dpcs

$$ ============================================================
$$ SECTION 11: SYSTEM STATE
$$ ============================================================
.echo ###SECTION:VM###
!vm 1

.echo ###SECTION:MEMUSAGE###
!memusage

$$ ============================================================
$$ SECTION 12: THREAD/PROCESS CONTEXT
$$ ============================================================
.echo ###SECTION:THREAD###
!thread

.echo ###SECTION:PROCESS###
!process

$$ ============================================================
$$ SECTION 13: IRQL & INTERRUPT STATE
$$ ============================================================
.echo ###SECTION:IRQL###
!irql

$$ ============================================================
$$ SECTION 14: BIT-FLIP TARGETS
$$ ============================================================
.echo ###SECTION:BITFLIP###
$$ Dump common pointer fields near corruption to look for single-bit errors
$$ If param1 is a pointer, dump it and nearby qwords
r $t7 = qwo(${$t5})
r $t8 = qwo(${$t5}+8)
r $t9 = qwo(${$t5}+16)
r $t10 = qwo(${$t5}+24)
.echo QWORD_0 = ${$t7}
.echo QWORD_1 = ${$t8}
.echo QWORD_2 = ${$t9}
.echo QWORD_3 = ${$t10}

$$ If these look like kernel pointers, note them for XOR analysis
.if (${$t7} >= 0xffff000000000000)
{
    .echo QWORD_0_IS_KERNEL_PTR = YES
}
.if (${$t8} >= 0xffff000000000000)
{
    .echo QWORD_1_IS_KERNEL_PTR = YES
}

.logclose
q
'@

    # Run cdb by piping the standard input stream
    Write-Host "  Launching cdb..." -NoNewline
    $output = $commands | & $debuggerPath -z "$dumpPath" -c ".logopen nul" 2>&1

    if ($?) {
        Write-Host " OK" -ForegroundColor Green
    } else {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Host $output -ForegroundColor DarkYellow
    }

    # Verify Output
    if (Test-Path $txtPath) {
        $size = (Get-Item $txtPath).Length / 1KB
        Write-Host "  → Created: $txtPath  ($([math]::Round($size,1)) KB)" -ForegroundColor Green
    } else {
        Write-Host "  → NO OUTPUT FILE CREATED" -ForegroundColor Red
        Write-Host $output -ForegroundColor DarkYellow
    }
}
Write-Host "Finished processing all files." -ForegroundColor Green