Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# -----------------------------
# 1. FORM SETUP (UX Improvements)
# -----------------------------
$form = New-Object System.Windows.Forms.Form
$form.Text = "System Monitor Pro"
$form.Size = New-Object System.Drawing.Size(500, 450) # Taller for bars
$form.StartPosition = "CenterScreen"
$form.BackColor = '#1E1E1E' # Modern Dark Grey instead of pure black
$form.FormBorderStyle = 'FixedSingle' # Prevent resizing
$form.MaximizeBox = $false
$form.TopMost = $true # Keep on top of other windows

# -----------------------------
# 2. HELPER FUNCTIONS
# -----------------------------
function New-DashboardLabel($name, $text, $top, $color) {
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Name = $name
    $lbl.Text = $text
    $lbl.Location = New-Object System.Drawing.Point(20, $top)
    $lbl.Size = New-Object System.Drawing.Size(450, 20)
    $lbl.Font = New-Object System.Drawing.Font("Consolas", 10, [System.Drawing.FontStyle]::Bold)
    $lbl.ForeColor = $color
    $lbl.BackColor = 'Transparent'
    $form.Controls.Add($lbl)
    return $lbl
}

function New-ProgressBar($top) {
    $bar = New-Object System.Windows.Forms.ProgressBar
    $bar.Location = New-Object System.Drawing.Point(20, $top)
    $bar.Size = New-Object System.Drawing.Size(440, 10)
    $bar.Style = 'Continuous'
    $form.Controls.Add($bar)
    return $bar
}

# -----------------------------
# 3. INITIALIZE CONTROLS
# -----------------------------
# CPU
$lblCPU = New-DashboardLabel "lblCPU" "CPU Load: Calculating..." 20 'Cyan'
$barCPU = New-ProgressBar 45

# RAM
$lblRAM = New-DashboardLabel "lblRAM" "RAM Usage: Calculating..." 65 'Lime'
$barRAM = New-ProgressBar 90

# DISK
$lblDisk = New-DashboardLabel "lblDisk" "Disk C: Calculating..." 110 'Orange'
$barDisk = New-ProgressBar 135

# TIME
$lblTime = New-DashboardLabel "lblTime" "Shift Remaining: Calculating..." 155 'White'
$barTime = New-ProgressBar 180

# UPTIME info (Static text, no bar needed)
$lblUptime = New-DashboardLabel "lblUptime" "Uptime: ..." 210 'LightGray'

# -----------------------------
# 4. DATA OBJECTS (Performance)
# -----------------------------
# Initialize PerformanceCounter for CPU (Much faster than WMI)
$cpuCounter = New-Object System.Diagnostics.PerformanceCounter("Processor", "% Processor Time", "_Total")
$null = $cpuCounter.NextValue() # First call always returns 0, so discard it

# Config: 12 Hour Shift Target
$startTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$targetTime = $startTime.AddHours(12)
$totalShiftSeconds = ($targetTime - $startTime).TotalSeconds

# -----------------------------
# 5. UPDATE LOGIC
# -----------------------------
function Update-FastMetrics {
    # --- CPU (Instant) ---
    $cpu = [math]::Round($cpuCounter.NextValue())
    $lblCPU.Text = "CPU Load: $cpu %"
    $barCPU.Value = [Math]::Min($cpu, 100)
    
    # Color Logic: Red if CPU spikes > 90%
    if ($cpu -gt 90) { $lblCPU.ForeColor = 'Red' } else { $lblCPU.ForeColor = 'Cyan' }

    # --- RAM (Fast) ---
    $os = Get-CimInstance Win32_OperatingSystem
    $totalRAM = $os.TotalVisibleMemorySize
    $freeRAM = $os.FreePhysicalMemory
    $usedRAM_Percent = [math]::Round((($totalRAM - $freeRAM) / $totalRAM) * 100)
    
    $lblRAM.Text = "RAM Usage: $usedRAM_Percent % (Free: $([math]::Round($freeRAM/1MB, 2)) GB)"
    $barRAM.Value = $usedRAM_Percent

    # --- TIME REMAINING (Fast) ---
    $now = Get-Date
    $remaining = $targetTime - $now
    
    if ($remaining.TotalSeconds -gt 0) {
        $lblTime.Text = "Shift Ends: $($targetTime.ToString('HH:mm')) (Left: $($remaining.Hours)h $($remaining.Minutes)m)"
        
        # Calculate progress inversely (Time Elapsed)
        $elapsed = ($now - $startTime).TotalSeconds
        $percentComplete = [math]::Round(($elapsed / $totalShiftSeconds) * 100)
        $barTime.Value = [Math]::Min([Math]::Max($percentComplete, 0), 100)
    } else {
        $lblTime.Text = "Shift Complete!"
        $barTime.Value = 100
        $lblTime.ForeColor = 'Red' # Alert that time is up
    }
}

function Update-SlowMetrics {
    # --- DISK (Slow) ---
    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
    $usedSpace = $disk.Size - $disk.FreeSpace
    $percentDisk = [math]::Round(($usedSpace / $disk.Size) * 100)
    
    $lblDisk.Text = "Disk (C:) Used: $percentDisk %"
    $barDisk.Value = $percentDisk

    # --- UPTIME ---
    $up = (Get-Date) - $startTime
    $lblUptime.Text = "System Uptime: $($up.Days)d $($up.Hours)h $($up.Minutes)m"
}

# -----------------------------
# 6. TIMERS (The "Engine")
# -----------------------------

# Fast Timer (Every 1 second) - Makes the UI feel "Live"
$timerFast = New-Object System.Windows.Forms.Timer
$timerFast.Interval = 1000 
$timerFast.Add_Tick({ Update-FastMetrics })

# Slow Timer (Every 30 seconds) - Saves resources on heavy queries
$timerSlow = New-Object System.Windows.Forms.Timer
$timerSlow.Interval = 30000 
$timerSlow.Add_Tick({ Update-SlowMetrics })

# -----------------------------
# 7. START
# -----------------------------
Update-FastMetrics
Update-SlowMetrics
$timerFast.Start()
$timerSlow.Start()

$form.ShowDialog()