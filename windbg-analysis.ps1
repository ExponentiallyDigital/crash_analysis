# Run as admin
$Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
#$dumpPath = "C:\WINDOWS\memory.dmp"
$dumpPath = "C:\users\andrew\desktop\2026-01-20 SECURE_KERNEL_ERROR (18b).DMP"
$outputPath = "C:\perflogs\$Timestamp`_dump_analysis_.txt"
$debuggerPath = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe"

# Build the debugger command block
$commands = ".logopen $outputPath`n"
#$commands += "!sysinfo machineid`n" # BIOS version and mobo revision
#$commands += "!sysinfo cpuinfo`n"  # processor info
$commands += "!thread`n"            # current thread & stack trace
$commands += "!analyze -v`n"
#$commands += "!process <adr> 7"    # show all threads in the crashed process, get address from !analyse eg
                                    # Attached Process ffffe70f73595040 Image: System
$commands += "!vm`n"                # memory stats & loaded processes
$commands += "!poolused 0 200`n"    # look for pool corruption
$commands += "lmof`n"               # list loaded modules (drivers), add "v" for verbose (timestamps + file description data)
$commands += "!locks`n"             # system locks
$commands += "!verifier`n"          # show verifier info
$commands += "!verifier 3`n"        # show verifier pool info
$commands += "!fltkd.filters`n"     # loaded filters
$commands += "!ndiskd.netadapter`n" # list of NICs
#$commands += "!handle 0 0`n"       # liist *all* handles, will be huge!
#$commands += "!process 0 0`n"      # what was running at crash time
#$commands += "!memusage`n"         # extremely detailed memory usage info, huge!
########
# Enable below when debugging suspectewd pool corruption, use‑after‑free, uninitialized memory, overwritten kernel structures,
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
$commands += ".logclose`n"
$commands += "q`n"

# Execute cdb with commands
$commands | & $debuggerPath -z $dumpPath
