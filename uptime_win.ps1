# =============================================================================
# 1. LOAD ASSEMBLIES
# =============================================================================
# Load the .NET assemblies required to build Windows Forms (GUI) and handle 
# graphical elements like Fonts, Colors, and Window Sizes.
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# =============================================================================
# 2. FORM SETUP
# =============================================================================
# Create the main window container.
$form = New-Object System.Windows.Forms.Form
$form.Text = "System Dashboard"

# Set the window size (Width: 460px, Height: 340px).
$form.Size = New-Object System.Drawing.Size(460, 340)

# Ensure the window opens directly in the center of the user's screen.
$form.StartPosition = "CenterScreen"

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
    # Get-CimInstance is the modern replacement for Get-WmiObject.
    # Win32_OperatingSystem holds boot time and memory info.
    $os = Get-CimInstance Win32_OperatingSystem
    $bootTime = $os.LastBootUpTime
    
    # Calculate Uptime: Current Time minus Last Boot Time.
    $uptime = (Get-Date) - $bootTime

    # --- Calculate Target & Remaining Time ---
    # Target is Boot Time + the 12-hour offset defined above.
    $targetTime = $bootTime + $Offset

    # Remaining is Target Time minus Current Time.
    $remaining = $targetTime - (Get-Date)
    
    # Logic check: If time has run out (negative seconds), force it to Zero
    # so the display doesn't show negative numbers (e.g., -05 minutes).
    if ($remaining.TotalSeconds -lt 0) {
        $remaining = [TimeSpan]::Zero
    }

    # --- Calculate Hardware Stats ---
    # RAM: WMI returns KB. Divide by 1MB to get GB. Round to 2 decimals.
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
    $labels.BootTime.Text   = "Boot Time:       $($bootTime.ToString('yyyy-MM-dd HH:mm:ss'))"
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
# 9. SHOW FORM
# =============================================================================
# Display the form as a modal dialog. The script pauses here until closed.
$form.ShowDialog()