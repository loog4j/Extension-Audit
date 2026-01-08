# Quick Deployment Guide - Browser Extension Audit

This guide walks you through deploying the browser extension audit script via scheduled tasks in an enterprise environment.

---

## 📋 Prerequisites Checklist

Before deployment, ensure you have:

- [ ] Script file: `extension_audit.ps1`
- [ ] Malicious extensions list (URL or file path)
- [ ] Admin access to target systems or GPO management rights
- [ ] Network access from endpoints to malicious list URL (if using URL)
- [ ] SIEM configured to collect Windows Application event logs

---

## 🚀 Deployment Methods

Choose the method that best fits your environment:

| Method | Best For | Difficulty | Centralized Management |
|--------|----------|------------|------------------------|
| **GPO Scheduled Task** | Domain-joined Windows environments | Medium | ✅ Yes |
| **PowerShell Script (Local)** | Testing, standalone systems | Easy | ❌ No |
| **SCCM Configuration Baseline** | SCCM-managed environments | Medium | ✅ Yes |
| **Intune Proactive Remediation** | Cloud-managed (Intune) devices | Medium | ✅ Yes |

---

## Method 1: GPO Scheduled Task (Recommended for Enterprises)

### Step 1: Prepare the Script Location

**Option A: Store in SYSVOL (Small Environments)**
```powershell
# On domain controller
Copy-Item .\extension_audit.ps1 -Destination "\\domain.com\SYSVOL\domain.com\scripts\"

# Verify
Test-Path "\\domain.com\SYSVOL\domain.com\scripts\extension_audit.ps1"
```

**Option B: Store in Central File Share (Large Environments)**
```powershell
# Create dedicated share
New-Item -Path "\\fileserver\SecurityScripts" -ItemType Directory
Copy-Item .\extension_audit.ps1 -Destination "\\fileserver\SecurityScripts\"

# Set permissions: Domain Computers (Read)
icacls "\\fileserver\SecurityScripts" /grant "Domain Computers:(RX)"
```

---

### Step 2: Create GPO Scheduled Task

1. **Open Group Policy Management Console**
   ```
   Run: gpmc.msc
   ```

2. **Create or Edit GPO**
   - Right-click your target OU → **Create a GPO in this domain, and Link it here**
   - Name: `Browser Extension Audit - Daily Scan`

3. **Navigate to Scheduled Tasks**
   ```
   Computer Configuration
   └── Preferences
       └── Control Panel Settings
           └── Scheduled Tasks
   ```

4. **Create New Scheduled Task**
   - Right-click **Scheduled Tasks** → **New** → **Scheduled Task (At least Windows 7)**

---

### Step 3: Configure Task Settings

#### **General Tab**

| Setting | Value |
|---------|-------|
| **Action** | Update |
| **Name** | Browser Extension Audit |
| **Description** | Daily scan of browser extensions for security monitoring |
| **User account** | `NT AUTHORITY\SYSTEM` |
| **Run whether user is logged on or not** | ✅ Checked |
| **Run with highest privileges** | ✅ Checked |
| **Hidden** | ⬜ Unchecked (Optional: check to hide from Task Scheduler UI) |

![General Tab Screenshot Placeholder]

---

#### **Triggers Tab**

Click **New** and configure:

| Setting | Value |
|---------|-------|
| **Begin the task** | On a schedule |
| **Settings** | Daily |
| **Start** | Today's date |
| **Start time** | `02:00:00` (2:00 AM) |
| **Recur every** | `1` days |
| **Enabled** | ✅ Checked |

**Advanced settings (expand):**
- **Delay task for up to (random delay):** `30 minutes` *(Spreads load across large fleets)*
- **Stop task if it runs longer than:** ⬜ Unchecked *(Let it complete)*

![Triggers Tab Screenshot Placeholder]

---

#### **Actions Tab**

Click **New** and configure:

| Setting | Value |
|---------|-------|
| **Action** | Start a program |
| **Program/script** | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| **Add arguments** | `-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File "\\domain.com\SYSVOL\domain.com\scripts\extension_audit.ps1"` |
| **Start in** | *(Leave blank)* |

**Important:** Replace `\\domain.com\SYSVOL\domain.com\scripts\` with your actual UNC path.

**For custom parameters:**
```powershell
-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File "\\domain.com\SYSVOL\domain.com\scripts\extension_audit.ps1" -LogName "Application" -SourceName "BrowserSecurity" -MaliciousExtensionsUrl "https://your-url.com/list.txt"
```

![Actions Tab Screenshot Placeholder]

---

#### **Conditions Tab**

| Setting | Recommended Value | Notes |
|---------|-------------------|-------|
| **Start only if the computer is on AC power** | ⬜ Unchecked | Allow laptops to run on battery |
| **Stop if the computer switches to battery** | ⬜ Unchecked | Don't interrupt mid-scan |
| **Start the task only if computer is idle** | ⬜ Unchecked | Run regardless of user activity |
| **Wake the computer to run this task** | ✅ Checked (Optional) | Wake sleeping workstations |
| **Start only if the following network connection is available** | ⬜ Unchecked | Run offline (if using file share list) |

---

#### **Settings Tab**

| Setting | Value | Notes |
|---------|-------|-------|
| **Allow task to be run on demand** | ✅ Checked | Allows manual testing |
| **Run task as soon as possible after scheduled start is missed** | ✅ Checked | Catch up if system was off |
| **If the task fails, restart every** | `15 minutes` | |
| **Attempt to restart up to** | `3 times` | |
| **Stop the task if it runs longer than** | ⬜ Unchecked | Or set to `1 hour` |
| **If the running task does not end when requested** | Do not start a new instance | Prevent overlapping runs |

---

### Step 4: Link GPO to OUs

1. **In Group Policy Management Console:**
   - Right-click target OU (e.g., `Workstations`)
   - Select **Link an Existing GPO**
   - Choose: `Browser Extension Audit - Daily Scan`

2. **Verify link:**
   ```
   OU: Workstations
   └── Linked GPOs
       └── Browser Extension Audit - Daily Scan [Enabled]
   ```

---

### Step 5: Test on Single Machine

**Before mass deployment, test on one workstation:**

1. **Force GPO update on test machine:**
   ```powershell
   gpupdate /force
   ```

2. **Verify scheduled task was created:**
   ```powershell
   Get-ScheduledTask -TaskName "Browser Extension Audit"
   ```

   Expected output:
   ```
   TaskPath  TaskName                   State
   --------  --------                   -----
   \         Browser Extension Audit    Ready
   ```

3. **Run task manually:**
   ```powershell
   Start-ScheduledTask -TaskName "Browser Extension Audit"
   ```

4. **Check Event Viewer:**
   ```
   Event Viewer → Windows Logs → Application
   Filter by Event ID: 9194
   Source: Browser Extension Alert
   ```

5. **Verify events appear:**
   - Should see one event per browser extension found
   - Check for both Information (benign) and Warning (malicious) events

**If successful, proceed with full deployment.**

---

### Step 6: Monitor Deployment

**Day 1-3: Monitor for issues**

```powershell
# On domain controller, check which machines received the GPO
Get-ADComputer -Filter * -SearchBase "OU=Workstations,DC=domain,DC=com" |
    Select-Object -ExpandProperty Name |
    ForEach-Object {
        $Computer = $_
        $Task = Get-ScheduledTask -TaskName "Browser Extension Audit" -CimSession $Computer -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            Computer = $Computer
            TaskExists = $Task -ne $null
            LastRunTime = $Task.LastRunTime
        }
    } | Format-Table
```

**Check SIEM for incoming events:**
- Verify Event ID 9194 logs are arriving
- Confirm event format is correct
- Check for any malicious detections (Warning events)

---

## Method 2: Local Scheduled Task (PowerShell)

### One-Line Deployment Script

**Copy and run this on target machine as Administrator:**

```powershell
# Copy script to local machine
$ScriptPath = "C:\Scripts\extension_audit.ps1"
New-Item -Path "C:\Scripts" -ItemType Directory -Force | Out-Null
Copy-Item "\\fileserver\SecurityScripts\extension_audit.ps1" -Destination $ScriptPath

# Create scheduled task
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File $ScriptPath"
$Trigger = New-ScheduledTaskTrigger -Daily -At 2:00AM
$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName "Browser Extension Audit" -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Description "Daily browser extension security scan"

# Test run
Start-ScheduledTask -TaskName "Browser Extension Audit"
Start-Sleep -Seconds 10
Get-EventLog -LogName Application -Source "Browser Extension Alert" -Newest 5 | Format-List
```

**Verify:**
```powershell
Get-ScheduledTask -TaskName "Browser Extension Audit" | Get-ScheduledTaskInfo
```

---

## Method 3: SCCM Configuration Baseline

### Step 1: Create Configuration Item

1. **Open SCCM Console:**
   ```
   Assets and Compliance → Compliance Settings → Configuration Items
   ```

2. **Create Configuration Item:**
   - Right-click → **Create Configuration Item**
   - Name: `Browser Extension Audit`
   - Type: **Windows Desktops and Servers**
   - Supported platforms: **Windows 10** (and others as needed)

3. **Add Setting:**
   - Type: **Script**
   - Setting type: **PowerShell**
   - Data type: **String**

4. **Discovery Script:**
   ```powershell
   # Always report non-compliant to trigger remediation
   return "NonCompliant"
   ```

5. **Remediation Script:**
   *(Paste entire content of extension_audit.ps1 here)*

   OR reference file:
   ```powershell
   # Download and execute from central location
   $ScriptUrl = "https://internal-repo.com/extension_audit.ps1"
   $TempPath = "$env:TEMP\extension_audit.ps1"
   Invoke-WebRequest -Uri $ScriptUrl -OutFile $TempPath
   & $TempPath
   Remove-Item $TempPath
   ```

6. **Compliance Rules:**
   - Click **New**
   - Name: `Always Remediate`
   - Rule type: **Value**
   - The value returned by the specified script: **Equals** → `Compliant`
   - ✅ Run the specified remediation script when this setting is noncompliant

---

### Step 2: Create Configuration Baseline

1. **Create Baseline:**
   ```
   Assets and Compliance → Compliance Settings → Configuration Baselines
   Right-click → Create Configuration Baseline
   ```

2. **Settings:**
   - Name: `Browser Extension Audit - Daily`
   - Click **Add** → **Configuration Items**
   - Select: `Browser Extension Audit`

---

### Step 3: Deploy Baseline

1. **Right-click baseline → Deploy**

2. **Configure deployment:**
   - Collection: `All Workstations`
   - Schedule: **Simple schedule** → **Daily**
   - Time: `2:00 AM`
   - ✅ Remediate noncompliant rules when supported
   - ✅ Allow remediation outside the maintenance window

3. **Monitor deployment:**
   ```
   Monitoring → Deployments
   Find: Browser Extension Audit - Daily
   ```

---

## Method 4: Intune Proactive Remediation

### Step 1: Create Remediation Script Package

1. **Navigate to:**
   ```
   Microsoft Endpoint Manager admin center
   → Reports → Endpoint Analytics → Proactive remediations
   ```

2. **Click:** `+ Create script package`

3. **Basics:**
   - Name: `Browser Extension Audit`
   - Description: `Daily browser extension security scan`

---

### Step 2: Configure Scripts

**Detection Script:**
```powershell
# Always trigger remediation
exit 1
```

**Remediation Script:**
*(Paste entire content of extension_audit.ps1)*

**Settings:**
- ✅ Run this script using the logged-on credentials: **No** (run as system)
- ✅ Enforce script signature check: **No**
- ✅ Run script in 64-bit PowerShell: **Yes**

---

### Step 3: Assign to Devices

1. **Assignments:**
   - Click **Add group**
   - Select: `All Devices` or specific security group

2. **Schedule:**
   - Run script: **Daily**
   - Time: `02:00 AM`

3. **Review + Create**

---

### Step 4: Monitor Results

1. **Check device status:**
   ```
   Endpoint Analytics → Proactive remediations
   → Browser Extension Audit → Device status
   ```

2. **Expected results:**
   - Detection status: Failed (exit code 1 - expected)
   - Remediation status: Success (script ran successfully)

---

## 📊 Post-Deployment Validation

### Week 1 Checklist

After deploying to production, validate the following:

#### Day 1
- [ ] Verify scheduled task exists on 10 random workstations
- [ ] Manually trigger task on test machine - confirm it completes
- [ ] Check Event Viewer on test machine for Event ID 9194
- [ ] Verify SIEM is receiving events from test machine

#### Day 3
- [ ] Check SIEM for event count across all endpoints
- [ ] Verify event format is parsing correctly in SIEM
- [ ] Review any malicious detections (Warning events)
- [ ] Check for any machines not reporting (troubleshoot)

#### Day 7
- [ ] Analyze extension inventory across organization
- [ ] Identify top 10 most common extensions
- [ ] Review any false positives in malicious list
- [ ] Document baseline for ongoing monitoring

---

### Validation Queries

**PowerShell: Check if task is running across fleet**
```powershell
$Computers = Get-ADComputer -Filter * -SearchBase "OU=Workstations,DC=domain,DC=com" | Select-Object -ExpandProperty Name

$Results = foreach ($Computer in $Computers) {
    try {
        $Task = Get-ScheduledTask -TaskName "Browser Extension Audit" -CimSession $Computer -ErrorAction Stop
        $Info = Get-ScheduledTaskInfo -TaskName "Browser Extension Audit" -CimSession $Computer

        [PSCustomObject]@{
            Computer = $Computer
            Status = "Running"
            LastRunTime = $Info.LastRunTime
            LastResult = $Info.LastTaskResult
        }
    } catch {
        [PSCustomObject]@{
            Computer = $Computer
            Status = "Not Found"
            LastRunTime = $null
            LastResult = $null
        }
    }
}

$Results | Export-Csv "TaskDeploymentStatus.csv" -NoTypeInformation
$Results | Group-Object Status | Format-Table Count, Name -AutoSize
```

**Expected output:**
```
Count Name
----- ----
  450 Running
   10 Not Found
```

---

**SIEM: Verify event collection (Splunk example)**
```spl
index=windows sourcetype="WinEventLog:Application" EventCode=9194 earliest=-24h
| stats count by host
| where count > 0
| stats count as ComputersReporting
```

Expected: Number should match your workstation count (allowing for powered-off machines)

---

## 🔧 Troubleshooting Common Deployment Issues

### Issue: Task exists but never runs

**Symptom:** Scheduled task shows "Ready" but never executes

**Causes & Solutions:**

1. **Task trigger not configured correctly**
   ```powershell
   Get-ScheduledTask -TaskName "Browser Extension Audit" |
       Select-Object -ExpandProperty Triggers
   ```
   - Verify `Enabled = True`
   - Check start date is not in the future

2. **Task running under wrong account**
   ```powershell
   Get-ScheduledTask -TaskName "Browser Extension Audit" |
       Select-Object -ExpandProperty Principal
   ```
   - Should be: `NT AUTHORITY\SYSTEM`
   - RunLevel should be: `Highest`

3. **Script path is invalid**
   - Test UNC path from workstation:
   ```powershell
   Test-Path "\\domain.com\SYSVOL\domain.com\scripts\extension_audit.ps1"
   ```

---

### Issue: Script runs but no events in Event Viewer

**Symptom:** Task completes (Last Run Result: 0x0) but no Event ID 9194

**Check 1: Run script manually**
```powershell
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "C:\Scripts\extension_audit.ps1"
```

Look for error messages.

**Check 2: Verify Event Log source exists**
```powershell
[System.Diagnostics.EventLog]::SourceExists("Browser Extension Alert")
```

If `False`, run once as Administrator:
```powershell
New-EventLog -LogName Application -Source "Browser Extension Alert"
```

**Check 3: Check for script errors in Event Viewer**
```
Windows Logs → Application
Source: "PowerShell" or "ScriptHost"
Look for errors matching the script run time
```

---

### Issue: Malicious list download fails

**Symptom:** Script reports "Failed to download malicious extensions list"

**Solution 1: Test network connectivity**
```powershell
Test-NetConnection raw.githubusercontent.com -Port 443
```

**Solution 2: Configure proxy**

Edit script to add proxy support (lines 176-179):
```powershell
function Get-MaliciousExtensionList {
    # Add these lines after param block:
    $ProxyUrl = "http://proxy.corp.local:8080"
    [System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy($ProxyUrl)
    $WebClient.Proxy = [System.Net.WebRequest]::DefaultWebProxy

    # Rest of function...
}
```

**Solution 3: Use local file instead**
```powershell
# Update GPO scheduled task arguments:
-File "\\domain.com\SYSVOL\domain.com\scripts\extension_audit.ps1" -MaliciousExtensionsPath "\\fileserver\security\malicious_extensions.txt"
```

---

### Issue: Events appear but SIEM not collecting them

**Check 1: Verify Windows Event Forwarding (if used)**
```powershell
# On workstation
Get-Service -Name "WinRM"  # Should be Running
Get-Service -Name "Wecsvc"  # Should be Running on collector

# Check subscriptions
wecutil enum-subscription
```

**Check 2: Verify SIEM agent is running**
```powershell
# Splunk Universal Forwarder
Get-Service -Name "SplunkForwarder"

# Winlogbeat
Get-Service -Name "winlogbeat"
```

**Check 3: Check SIEM agent configuration**

Splunk `inputs.conf`:
```ini
[WinEventLog://Application]
disabled = 0
index = windows
```

Winlogbeat `winlogbeat.yml`:
```yaml
winlogbeat.event_logs:
  - name: Application
    event_id: 9194
```

---

## 📞 Support & Next Steps

### If deployment is successful:
1. ✅ Update malicious list weekly (see README.md)
2. ✅ Create SIEM alerts for malicious detections
3. ✅ Establish incident response workflow
4. ✅ Document remediation procedures

### If you encounter issues:
1. Review troubleshooting section above
2. Check README.md FAQ section
3. Test script manually on problem machine
4. Review Windows Event Logs for errors
5. Contact your security team or open GitHub issue

---

## 📚 Additional Resources

- **Main Documentation:** README.md
- **Script Source:** extension_audit.ps1
- **Sample Malicious List:** malicious_extensions.txt
- **SIEM Integration Examples:** README.md → SIEM Integration section

---

**Deployment complete?** Return to [README.md](README.md) for SIEM integration and maintenance procedures.
