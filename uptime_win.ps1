# =============================================================================
# 1. LOAD ASSEMBLIES
# =============================================================================
# Load the .NET assemblies required to build Windows Forms (GUI) and handle 
# graphical elements like Fonts, Colors, and Window Sizes.
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Minimize the PowerShell console window (host) immediately
Add-Type -Name Window -Namespace Console -MemberDefinition '
[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

public const int SW_MINIMIZE = 6;
'

# Get the main window handle of this PowerShell process
$consoleHwnd = (Get-Process -Id $PID).MainWindowHandle

# Minimize it
[Console.Window]::ShowWindow($consoleHwnd, 6) | Out-Null

# =============================================================================
# 2. FORM SETUP
# =============================================================================
# Create the main window container.
$form = New-Object System.Windows.Forms.Form
$form.Text = "System Dashboard"

# Set the window size (Width: 460px, Height: 340px).
$form.Size = New-Object System.Drawing.Size(460, 340)

# Ensure the window opens directly in the center of the user's screen.
#$form.StartPosition = "CenterScreen"

# Set a black background for a high-contrast, "terminal" look.
$form.BackColor = 'Black'

# =============================================================================
# 3. HELPER FUNCTION
# =============================================================================
# A helper function to generate standard labels. This avoids repeating code 
# for every single line of text on the dashboard.
# Params:
#   $text:  Initial text to display (usually empty).
#   $top:   The Y-coordinate (vertical position).
#   $color: The text color (System.Drawing.Color name).
function New-DashboardLabel($text, $top, $color) {
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = $text
    
    # Set position: X=20 (left margin), Y=$top (dynamic).
    $lbl.Location = New-Object System.Drawing.Point(20, $top)
    
    # Set size wide enough to hold the data strings.
    $lbl.Size = New-Object System.Drawing.Size(420, 22)
    
    # Use 'Consolas' (monospaced font) to ensure numbers align vertically.
    $lbl.Font = New-Object System.Drawing.Font("Consolas", 11)
    
    $lbl.ForeColor = $color
    $lbl.BackColor = 'Black' # Match form background
    return $lbl
}

# =============================================================================
# 4. INITIALIZE LABELS
# =============================================================================
# Use a Hash table to store labels. This allows us to reference them by name 
# (e.g., $labels.RAM) later in the script.
$labels = @{
    # Key Name   = Call Function (Text, Top Position, Color)
    Uptime       = New-DashboardLabel ""  20  'Yellow'
    BootTime     = New-DashboardLabel ""  45  'Cyan'
    TargetTime   = New-DashboardLabel ""  70  'Orange'
    Remaining    = New-DashboardLabel ""  95  'Red'
    RAM          = New-DashboardLabel "" 120  'Lime'
    Disk         = New-DashboardLabel "" 145  'Lime'
    Handles      = New-DashboardLabel "" 170  'Magenta'
    Threads      = New-DashboardLabel "" 195  'Magenta'
    Updated      = New-DashboardLabel "" 220  'DarkGray'
}

# Loop through the hash table and add every label to the Form's Controls collection.
# If you skip this, the labels exist in memory but won't appear on screen.
foreach ($lbl in $labels.Values) { $form.Controls.Add($lbl) }

# =============================================================================
# 5. CONFIGURATION
# =============================================================================
# Define the target duration (e.g., a 12-hour shift or maintenance window).
# Change this value to adjust the countdown timer.
$Offset = New-TimeSpan -Hours 11 -Minutes 50

# =============================================================================
# 6. UPDATE LOGIC
# =============================================================================
# This function gathers system data and updates the label text.
function Update-Dashboard {
    param($Offset)

    # --- Retrieve OS Data ---
    # Use kernel monotonic tick counter for accurate uptime (matches WinDbg !sysinfo).
    $perf = Get-CimInstance Win32_PerfFormattedData_PerfOS_System
    $uptime = [TimeSpan]::FromSeconds($perf.SystemUpTime)
    
    # Kernel boot time = now - monotonic uptime
    $kernelBootTime = (Get-Date) - $uptime

    # --- Calculate Target & Remaining Time ---
    # Target is Kernel Boot Time + the offset defined above.
    $targetTime = $kernelBootTime + $Offset

    # Remaining is Target Time minus Current Time.
    $remaining = $targetTime - (Get-Date)
    
    # ────────────────────────────────────────────────
    # 30-MINUTE EARLY WARNING ALARM
    # ────────────────────────────────────────────────
    $earlyWarningMinutes = 30

    if ($remaining.TotalMinutes -le $earlyWarningMinutes -and $remaining.TotalMinutes -gt 0) {
        # Only trigger once
        if (-not (Get-Variable -Name "AlarmTriggered" -Scope Script -ErrorAction SilentlyContinue)) {
            Set-Variable -Name "AlarmTriggered" -Value $true -Scope Script

            Write-Host "30-min warning triggered! Uptime: $($uptime.ToString('dd\.hh\:mm'))" -ForegroundColor Yellow

            # Audible: Exclamation sound ×3
            $sound = [System.Media.SystemSounds]::Exclamation
            1..5 | ForEach-Object {
                $sound.Play()
                Start-Sleep -Milliseconds 700
            }

            # Visual: Flash background
            $originalColor = $form.BackColor
            $form.BackColor = 'OrangeRed'
            Start-Sleep -Seconds 1
            $form.BackColor = 'Red'
            Start-Sleep -Seconds 1
            $form.BackColor = 'Orange'
            Start-Sleep -Seconds 1
            $form.BackColor = $originalColor

            # Popup message (fixed quotes and parentheses)
            Add-Type -AssemblyName System.Windows.Forms

            # Custom centered warning on SECONDARY monitor (left screen)
            $alertForm = New-Object System.Windows.Forms.Form
            $alertForm.Text = "Uptime Crash Warning - 30 Minutes Remaining"
            $alertForm.Size = New-Object System.Drawing.Size(500, 220)
            $alertForm.StartPosition = "Manual"  # We set location manually
            $alertForm.BackColor = 'DarkRed'
            $alertForm.ForeColor = 'White'
            $alertForm.Font = New-Object System.Drawing.Font("Segoe UI", 11)
            $alertForm.FormBorderStyle = 'FixedDialog'
            $alertForm.MaximizeBox = $false
            $alertForm.MinimizeBox = $false
            $alertForm.TopMost = $true   # Stays on top

            # Center on secondary monitor (left one)
            $screens = [System.Windows.Forms.Screen]::AllScreens
            $secondary = $screens | Where-Object { -not $_.Primary } | Select-Object -First 1

            if ($null -eq $secondary) { $secondary = $screens | Where-Object { $_.Primary } | Select-Object -First 1 }

            $bounds = $secondary.Bounds

            $x = $bounds.Left + [math]::Round(($bounds.Width - $alertForm.Width) / 2)
            $y = $bounds.Top  + [math]::Round(($bounds.Height - $alertForm.Height) / 2)

            $alertForm.Location = New-Object System.Drawing.Point($x, $y)

            # Message label
            $lblMsg = New-Object System.Windows.Forms.Label
            $lblMsg.Text = "WARNING: System is approaching expected crash window!`r`n`r`n" +
                        "Remaining: $($remaining.Hours)h $($remaining.Minutes)m`r`n" +
                        "Current uptime: $($uptime.Days) days $($uptime.Hours)h $($uptime.Minutes)m`r`n`r`n" +
                        "Save work and prepare to reboot soon."
            $lblMsg.AutoSize = $false
            $lblMsg.Location = New-Object System.Drawing.Point(20, 20)
            $lblMsg.Size = New-Object System.Drawing.Size(460, 120)
            $lblMsg.TextAlign = 'MiddleCenter'
            $alertForm.Controls.Add($lblMsg)

            # OK button
            $btnOK = New-Object System.Windows.Forms.Button
            $btnOK.Text = "OK"
            $btnOK.Location = New-Object System.Drawing.Point(200, 160)
            $btnOK.Size = New-Object System.Drawing.Size(100, 35)
            $btnOK.DialogResult = [System.Windows.Forms.DialogResult]::OK
            $alertForm.AcceptButton = $btnOK
            $alertForm.Controls.Add($btnOK)

            # Show as dialog (blocks until closed)
            $alertForm.ShowDialog() | Out-Null
            $alertForm.Dispose()
        }
    }
    elseif ($remaining.TotalMinutes -le 0) {
        # Check if final alarm has already been triggered (prevents repeat every 30s)
        if (-not (Get-Variable -Name "FinalAlarmTriggered" -Scope Script -ErrorAction SilentlyContinue)) {
            Set-Variable -Name "FinalAlarmTriggered" -Value $true -Scope Script
            [System.Media.SystemSounds]::Hand.Play()
            # Optional: add a one-time popup here if you want
            [System.Windows.Forms.MessageBox]::Show("Target time has been reached!", "Uptime Alert")
        }
    }

    # ────────────────────────────────────────────────
    # Logic check: If time has run out (negative seconds), force it to Zero
    # so the display doesn't show negative numbers (e.g., -05 minutes).
    if ($remaining.TotalSeconds -lt 0) {
        $remaining = [TimeSpan]::Zero
    }

    # --- Calculate Hardware Stats ---
    # RAM: WMI returns KB. Divide by 1MB to get GB. Round to 2 decimals.
    $os = Get-CimInstance Win32_OperatingSystem
    $freeRAM_GB = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
    
    # Disk: Get all Fixed Local Disks (DriveType=3). 
    # Measure-Object sums the FreeSpace of all drives (C:, D:, etc.).
    # Divide by 1TB to get Terabytes.
    $drives = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3"
    $freeDisk_TB = [math]::Round(($drives.FreeSpace | Measure-Object -Sum).Sum / 1TB, 3)
    
    # Processes: Get all running processes to count Handles and Threads.
    # This indicates how "busy" the kernel is.
    $procs = Get-Process
    $totalHandles = ($procs.Handles | Measure-Object -Sum).Sum
    $totalThreads = ($procs.Threads.Count | Measure-Object -Sum).Sum

    # --- Update UI Text ---
    # Update the .Text property of the labels.
    # We use sub-expressions $() to calculate values inside strings.
    $labels.Uptime.Text     = "Uptime:          $($uptime.Days) days $($uptime.Hours) hours $($uptime.Minutes) minutes"
    
    # Format dates as 'yyyy-MM-dd HH:mm:ss' for readability.
    $labels.BootTime.Text   = "Boot Time:       $($kernelBootTime.ToString('yyyy-MM-dd HH:mm:ss'))"
    $labels.TargetTime.Text = "Boot +11h 50m:   $($targetTime.ToString('yyyy-MM-dd HH:mm:ss'))"
    
    # Display remaining hours and minutes.
    $labels.Remaining.Text  = "Remaining:       $($remaining.Hours)h $($remaining.Minutes)m"
    
    $labels.RAM.Text        = "Free RAM:        $freeRAM_GB GB"
    $labels.Disk.Text       = "Free Disk Space: $freeDisk_TB TB"
    
    # Format specifier "{0:N0}" adds thousands separators (e.g., 1,200 vs 1200).
    $labels.Handles.Text    = "Total Handles:   {0:N0}" -f $totalHandles
    $labels.Threads.Text    = "Total Threads:   {0:N0}" -f $totalThreads
    
    # Timestamp to show the user the dashboard is active and not frozen.
    $labels.Updated.Text    = "Updated:         $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
}

# =============================================================================
# 7. TIMER SETUP
# =============================================================================
# Create a Forms Timer to trigger the update automatically.
$timer = New-Object System.Windows.Forms.Timer

# Set interval to 30,000 milliseconds (30 seconds).
$timer.Interval = 30000

# Add the event: Every 30s, run Update-Dashboard.
$timer.Add_Tick({ Update-Dashboard -Offset $Offset })

# =============================================================================
# 8. STARTUP
# =============================================================================
# Run the update ONCE immediately. Otherwise, the form would be blank 
# for the first 30 seconds until the timer ticks.
Update-Dashboard -Offset $Offset

# Start the timer loop.
$timer.Start()

# =============================================================================
# POSITION FORM ON SECONDARY MONITOR (LEFT SIDE), BOTTOM-RIGHT CORNER
# =============================================================================

# Force handle creation
$form.Handle | Out-Null
Start-Sleep -Milliseconds 300  # Give handle time to initialize

# Get screens
$screens = [System.Windows.Forms.Screen]::AllScreens

# Explicitly select the left/secondary monitor (DISPLAY2, non-primary)
$secondary = $screens | Where-Object { -not $_.Primary } | Select-Object -First 1

if ($null -eq $secondary) {
    Write-Host "No secondary found - falling back to primary" -ForegroundColor Yellow
    $secondary = $screens | Where-Object { $_.Primary } | Select-Object -First 1
}

$bounds = $secondary.Bounds

# Form dimensions (match your original size)
$width  = $form.Width   # 460
$height = $form.Height  # 340

# Bottom-right of LEFT monitor:
# Right edge = $bounds.Right (0 in your case)
# Bottom edge = $bounds.Bottom (800)
$x = $bounds.Right - $width + 7     # e.g., 0 - 460 - 40 = -500 (right edge of left monitor)
$y = $bounds.Bottom - $height - 0   # e.g., 800 - 340 - 60 = 400 (above bottom)

# Apply position
$form.Location = New-Object System.Drawing.Point($x, $y)

# Ensure visible and not minimized/maximized unexpectedly
$form.WindowState = [System.Windows.Forms.FormWindowState]::Normal
$form.BringToFront()

# Debug (keep for now, remove later if happy)
Write-Host "Secondary monitor: $($secondary.DeviceName)" -ForegroundColor Magenta
Write-Host "Bounds: X=$($bounds.X) to $($bounds.Right), Y=$($bounds.Y) to $($bounds.Bottom)" -ForegroundColor Magenta
Write-Host "Form positioned at: X=$x, Y=$y (size $($width)x$($height))" -ForegroundColor Magenta

# =============================================================================
# 9. SHOW FORM
# =============================================================================
# Display the form as a modal dialog. The script pauses here until closed.
$form.ShowDialog()