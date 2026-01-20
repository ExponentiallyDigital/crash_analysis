# extract a subset of data from the CSV file
# useful for very large files

$CsvPath = "C:\PerfLogs\2026-01-19 SECURE_KERNEL_ERROR (18b).DMP\2026-01-18_20-26-40_perfdata_log.json"
$csv = Import-Csv $CsvPath

# Check if there are enough rows
if ($csv.Count -lt 100) {
    Write-Host "Input file has fewer than 100 rows ($($csv.Count) rows). No output file created."
    exit
}

# Get first and last 5 rows, plus every 20th row
$samples = @()
$samples += $csv[0..4]  # Start of the captured perf data
$samples += $csv | Select-Object -Index (20, 40, 60, 80, 100, 120, 140, 160, 180, 200, 220, 240, 260, 280, 300, 320, 340, 360, 380, 400, 420, 440, 460, 480, 500, 520, 540, 560, 580, 600, 620, 640, 660, 680, 700) -ErrorAction SilentlyContinue
$samples += $csv[-20..-1]  # Pre-crash, assuming the script gets killed by a crash vs user termination
$samples = $samples | Sort-Object -Unique
$BaseName = [System.IO.Path]::GetFileNameWithoutExtension($CsvPath)
$OutputCsv = "C:\perflogs\$($BaseName)_extract.csv"
$samples | Export-Csv $OutputCsv -NoTypeInformation

# Column summary file
#$csv[0].PSObject.Properties.Name | Out-File "C:\perflogs\$($BaseName)_column_names.txt" -Append