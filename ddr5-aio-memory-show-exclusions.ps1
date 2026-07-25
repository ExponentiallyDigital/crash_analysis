$whea = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WHEA"
$pages = $whea.BadPages
$idx = 0
while($idx -le $pages.Count) {
     $slice = $pages[$idx..($idx+7)]
     [array]::Reverse($slice)
     $page = (($slice | foreach { $_.ToString("X2") }) -join "")
     Write-Output $page
     $idx = $idx + 8
 }