$tasks = Get-ScheduledTask
foreach ($task in $tasks) {
    $action = $task.Actions | Where-Object { $_.Execute }
    if ($action) {
        # Trim quotes and spaces to ensure Test-Path works correctly
        $rawPath = $action.Execute
        $cleanPath = $rawPath.Trim('"').Trim("'").Trim()
        
        # We only care about local disk paths
        if ($cleanPath -like "C:\*") {
            if (-not (Test-Path -Path $cleanPath -ErrorAction SilentlyContinue)) {
                Write-Host "`n[!] CONFIRMED GHOST FOUND" -ForegroundColor Yellow
                Write-Host "Task Name: $($task.TaskName)" -ForegroundColor White
                Write-Host "Missing Path: $cleanPath" -ForegroundColor Gray
                
                # The Prompt
                $title = "Delete Ghost Task"
                $message = "Do you want to permanently delete the task '$($task.TaskName)'?"
                $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Deletes the scheduled task."
                $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Keeps the task."
                $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
                
                $result = $host.ui.PromptForChoice($title, $message, $options, 1) 
                
                if ($result -eq 0) {
                    Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false
                    Write-Host "DELETED: $($task.TaskName)" -ForegroundColor Red
                } else {
                    Write-Host "SKIPPED: $($task.TaskName)" -ForegroundColor Cyan
                }
            }
        }
    }
}
Write-Host "`nScan Complete." -ForegroundColor Green