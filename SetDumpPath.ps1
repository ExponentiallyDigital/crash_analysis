	# This script ensures the dump directory exists and sets a unique filename so Windows will not overwrite the dump

	# !!!!!!!!!!!!!
	# !!!!!!!!!!!!! edit below line:
	# !!!!!!!!!!!!!
	$DumpRoot = "C:\CrashDumps"
	
	# Ensure directory exists
	if (!(Test-Path $DumpRoot)) {
	    New-Item -ItemType Directory -Path $DumpRoot | Out-Null
	}
	
	# Generate unique filename
	$Timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
	$DumpFile = "$DumpRoot\FullDump_$Timestamp.dmp"
	
	# CrashControl registry path
	$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"
	
	# Ensure full dump mode
	Set-ItemProperty -Path $RegPath -Name "CrashDumpEnabled" -Value 1
	
	# Set dump filename
	Set-ItemProperty -Path $RegPath -Name "DumpFile" -Value $DumpFile
