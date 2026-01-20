# 
$Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$outputPath = "C:\perflogs\$Timestamp`_Verifier_status.txt"
verifier /query > $outputPath
