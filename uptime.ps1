$u=(Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime; "{0} days {1} hours {2} minutes" -f $u.Days,$u.Hours,$u.Minutes
Read-Host "Press Enter to continue"
