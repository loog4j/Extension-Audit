# Browser Extension Audit Tool

A lightweight PowerShell script for auditing browser extensions across Windows endpoints. Designed for enterprise security teams to detect malicious browser extensions by comparing installed extensions against a known malicious extension ID list.

## Overview

This tool silently enumerates all browser extensions installed on a Windows system across all user profiles and logs findings to Windows Event Viewer. Security teams can then pull these logs into their SIEM for analysis, alerting, and incident response.

**Key Features:**
- Scans Chrome, Edge, Brave, and Firefox extensions
- Scans all user profiles automatically (not just current user)
- Compares against known malicious extension ID list
- Logs to Windows Event Viewer in Sysmon-compatible format
- Silent execution (perfect for scheduled tasks)
- No dependencies - uses built-in PowerShell
- SIEM-ready output (Event ID 9194)

---

## Quick Start

### 1. Download the Script
```powershell
# Clone or download extension_audit.ps1 to a known location
# Example: C:\Scripts\extension_audit.ps1
```

### 2. Run Once Manually (First Time Setup)
```powershell
# Open PowerShell as Administrator
.\extension_audit.ps1
```

**What happens:**
- Creates Event Log source "Browser Extension Alert" (requires admin on first run)
- Downloads malicious extension list from configured URL
- Scans all extensions on the system
- Writes one Event Log entry per extension found
- Outputs summary to console

### 3. Check Event Viewer
1. Open **Event Viewer** (`eventvwr.msc`)
2. Navigate to: **Windows Logs** → **Application**
3. Filter by **Event ID 9194** and **Source: Browser Extension Alert**
4. Look for **Warning** events (malicious) vs **Information** events (benign)

---

## 📋 Requirements

| Requirement | Details |
|-------------|---------|
| **Operating System** | Windows 7 / Server 2008 R2 or later |
| **PowerShell** | Version 3.0+ (built-in on Windows 8+) |
| **Permissions** | Administrator (first run only to create Event Log source) |
| **Network Access** | HTTPS access to malicious extension list URL (or use local file) |
| **Supported Browsers** | Chrome, Edge, Brave, Firefox |

---

## 🔧 How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. Download Malicious Extension List                           │
│    (from URL or local file)                                     │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. Enumerate All User Profiles                                 │
│    (via WMI - S-1-5-21-* SIDs only)                            │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. For Each Browser (Chrome, Edge, Brave, Firefox)            │
│    Scan all profiles (Default, Profile 1, Profile 2, etc.)     │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. Read Extension Manifests                                    │
│    Extract: Extension ID, Name, Version                        │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ 5. Check for Collision                                         │
│    Is Extension ID in malicious list? → IsMalicious = TRUE/FALSE │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ 6. Write to Event Log                                          │
│    - Benign: Event Type = Information                          │
│    - Malicious: Event Type = Warning ⚠️                        │
└─────────────────────────────────────────────────────────────────┘
```

**Every extension found generates one Event Log entry.**

---

## 📝 Usage

### Basic Usage (Uses Defaults)
```powershell
.\extension_audit.ps1
```

### Custom Event Log Settings
```powershell
.\extension_audit.ps1 -LogName "Application" -SourceName "BrowserSecurity"
```

### Filter by Extension Name
```powershell
# Only log extensions matching "adblock" (case-insensitive regex)
.\extension_audit.ps1 -Match "adblock"
```

### Use Custom Malicious List URL
```powershell
.\extension_audit.ps1 -MaliciousExtensionsUrl "https://your-domain.com/malicious_list.txt"
```

### Use Local File Instead of URL
```powershell
# Local file path
.\extension_audit.ps1 -MaliciousExtensionsPath "C:\Security\malicious_extensions.txt"

# Network file share (UNC path)
.\extension_audit.ps1 -MaliciousExtensionsPath "\\fileserver\security\malicious_extensions.txt"
```

---

## 📊 Event Log Format

### Event Details
- **Log Name:** Application (configurable)
- **Source:** Browser Extension Alert (configurable)
- **Event ID:** 9194
- **Event Type:**
  - **Information** = Benign extension
  - **Warning** = Malicious extension detected ⚠️

### Event Message Format (Sysmon-Style)
```
RuleName: -
UtcTime: 2026-01-07 19:30:45.123
Hostname: DESKTOP-PC01
UserName: john.doe
Browser: Chrome
Profile: Default
ExtensionId: aapbdbdomjkkjkaonfhkkikfgjllcleb
Name: Malicious Crypto Miner
Version: 1.2.3
Malicious: TRUE
```

### Field Descriptions

| Field | Description |
|-------|-------------|
| **RuleName** | Always "-" (reserved for future use) |
| **UtcTime** | Timestamp in UTC when extension was detected |
| **Hostname** | Computer name where extension was found |
| **UserName** | Windows user profile name (not SID) |
| **Browser** | Browser name (Chrome, Edge, Brave, Firefox) |
| **Profile** | Browser profile name (Default, Profile 1, etc.) |
| **ExtensionId** | 32-character unique extension identifier |
| **Name** | Human-readable extension name |
| **Version** | Extension version number |
| **Malicious** | TRUE (malicious) or FALSE (benign) |

---

## 🗓️ Deployment via Scheduled Task

### Option 1: Deploy via Group Policy (GPO)

**Best for:** Enterprise domain environments

1. **Create Scheduled Task in Group Policy**
   - Open **Group Policy Management Console** (`gpmc.msc`)
   - Navigate to: **Computer Configuration** → **Preferences** → **Control Panel Settings** → **Scheduled Tasks**
   - Right-click → **New** → **Scheduled Task (At least Windows 7)**

2. **General Tab**
   - Name: `Browser Extension Audit`
   - User: `NT AUTHORITY\SYSTEM`
   - ✅ Run whether user is logged on or not
   - ✅ Run with highest privileges

3. **Triggers Tab**
   - Click **New**
   - Begin the task: **On a schedule**
   - Settings: **Daily** at **2:00 AM** (or your preferred time)
   - ✅ Enabled

4. **Actions Tab**
   - Click **New**
   - Action: **Start a program**
   - Program/script: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
   - Add arguments: `-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File "\\domain.com\SYSVOL\domain.com\scripts\extension_audit.ps1"`
   - (Place script in SYSVOL for centralized access)

5. **Conditions Tab**
   - ⬜ Start only if computer is on AC power (uncheck for laptops)
   - ✅ Wake the computer to run this task (optional)

6. **Settings Tab**
   - ✅ Allow task to be run on demand
   - ⬜ Stop task if it runs longer than: (uncheck or set to 1 hour)
   - If the task fails, restart every: **15 minutes**
   - Attempt to restart up to: **3 times**

7. **Link GPO to OUs** containing workstations

**Result:** Script runs daily on all domain-joined workstations

---

### Option 2: Local Scheduled Task (Single Machine)

**Best for:** Testing, non-domain environments, or individual systems

```powershell
# Run this PowerShell command as Administrator to create scheduled task

$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File C:\Scripts\extension_audit.ps1"

$Trigger = New-ScheduledTaskTrigger -Daily -At 2:00AM

$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Register-ScheduledTask -TaskName "Browser Extension Audit" -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Description "Daily browser extension audit for security monitoring"
```

**Verify scheduled task:**
```powershell
Get-ScheduledTask -TaskName "Browser Extension Audit"
```

**Test run immediately:**
```powershell
Start-ScheduledTask -TaskName "Browser Extension Audit"
```

---

### Option 3: Deploy via SCCM / Intune

**Best for:** Organizations using Microsoft Endpoint Manager

#### **SCCM Configuration Baseline**

1. **Create Configuration Item**
   - Type: **Script**
   - Script Type: **PowerShell**
   - Discovery Script: *(Leave empty - always run)*
   - Remediation Script: *Paste extension_audit.ps1 content*

2. **Create Configuration Baseline**
   - Add Configuration Item
   - Schedule: **Daily**

3. **Deploy to Collection**
   - Target: **All Workstations**
   - Remediation: ✅ Enabled

#### **Intune Proactive Remediation**

1. **Navigate to:** Endpoint Analytics → Proactive remediations
2. **Create script package:**
   - Detection script: `exit 1` (always triggers remediation)
   - Remediation script: *Paste extension_audit.ps1 content*
   - Run script in 64-bit PowerShell: **Yes**
   - Run as system: **Yes**
   - Enforce script signature check: **No**
3. **Schedule:** Daily
4. **Assign to:** All Devices group

---

## 🔍 SIEM Integration

### Event Log Query Basics

**Query all extension scans:**
```xml
Event ID = 9194
Source = "Browser Extension Alert"
```

**Query only malicious detections:**
```xml
Event ID = 9194
EntryType = Warning
```
or
```xml
Event ID = 9194
Message contains "Malicious: TRUE"
```

---

### Splunk Integration

**1. Configure Windows Event Log Forwarding**

On Windows endpoints (via GPO or local):
```xml
<!-- C:\Windows\System32\winevt\Logs\subscription.xml -->
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
  <Query>
    <Select Path="Application">*[System[(EventID=9194)]]</Select>
  </Query>
</Subscription>
```

Or install **Splunk Universal Forwarder** with inputs.conf:
```ini
[WinEventLog://Application]
disabled = 0
index = windows
sourcetype = WinEventLog:Application
whitelist = 9194
```

**2. Splunk Search Queries**

**All extensions scanned today:**
```spl
index=windows sourcetype="WinEventLog:Application" EventCode=9194 earliest=-24h
| stats count by Hostname, UserName, Browser, ExtensionId, Name
```

**Malicious extensions detected:**
```spl
index=windows sourcetype="WinEventLog:Application" EventCode=9194 Type=Warning
| rex field=Message "ExtensionId: (?<ExtID>[^\r\n]+)"
| rex field=Message "Name: (?<ExtName>[^\r\n]+)"
| rex field=Message "Hostname: (?<Host>[^\r\n]+)"
| rex field=Message "UserName: (?<User>[^\r\n]+)"
| table _time, Host, User, ExtID, ExtName
| sort -_time
```

**Dashboard - Top 10 Extensions Across Fleet:**
```spl
index=windows sourcetype="WinEventLog:Application" EventCode=9194 earliest=-7d
| rex field=Message "ExtensionId: (?<ExtID>[^\r\n]+)"
| rex field=Message "Name: (?<ExtName>[^\r\n]+)"
| stats count by ExtName, ExtID
| sort -count
| head 10
```

**Alert - New Malicious Extension Detected:**
```spl
index=windows sourcetype="WinEventLog:Application" EventCode=9194 Type=Warning
| rex field=Message "Malicious: TRUE"
| table _time, ComputerName, User, ExtensionId, Name
```
- Set trigger: **Number of results > 0**
- Throttle: **5 minutes**
- Action: Email security team

---

### Microsoft Sentinel (Azure) Integration

**1. Configure Data Connector**
- Navigate to: **Sentinel** → **Data connectors** → **Windows Security Events via AMA**
- Create Data Collection Rule (DCR)
- Filter: **Event ID 9194**

**2. KQL Queries**

**All malicious extensions detected:**
```kql
Event
| where EventID == 9194
| where EventLevelName == "Warning"
| extend ExtensionData = parse_xml(EventData)
| project TimeGenerated, Computer, EventLevelName, RenderedDescription
| order by TimeGenerated desc
```

**Count of malicious extensions by computer:**
```kql
Event
| where EventID == 9194 and EventLevelName == "Warning"
| summarize MaliciousCount = count() by Computer
| order by MaliciousCount desc
```

**3. Create Analytics Rule (Alert)**
- Rule name: **Malicious Browser Extension Detected**
- Severity: **High**
- Query:
```kql
Event
| where EventID == 9194
| where EventLevelName == "Warning"
| extend Message = tostring(RenderedDescription)
| where Message contains "Malicious: TRUE"
```
- Frequency: **Every 5 minutes**
- Incident grouping: **Group all alerts into a single incident**
- Actions: Create incident, notify SOC

---

### Elastic Stack (ELK) Integration

**1. Winlogbeat Configuration**

`C:\ProgramData\Elastic\Beats\winlogbeat\winlogbeat.yml`:
```yaml
winlogbeat.event_logs:
  - name: Application
    event_id: 9194
    processors:
      - drop_event:
          when:
            not:
              equals:
                event_id: 9194

output.elasticsearch:
  hosts: ["https://your-elk-server:9200"]
  index: "browser-extensions-%{+yyyy.MM.dd}"
```

**2. Elasticsearch Query**

**Find malicious extensions:**
```json
GET /browser-extensions-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "match": { "event_id": 9194 }},
        { "match": { "level": "Warning" }}
      ]
    }
  },
  "sort": [
    { "@timestamp": "desc" }
  ]
}
```

**3. Kibana Visualization**
- Create index pattern: `browser-extensions-*`
- Visualization: Pie chart of Browser field
- Dashboard: Table showing Computer, User, Extension Name, Malicious status

---

### QRadar Integration

**1. Configure Log Source**
- Log Source Type: **Microsoft Windows Security Event Log**
- Protocol: **WinCollect** or **Syslog**
- Filter by Event ID: **9194**

**2. AQL Queries**

**Malicious extensions detected in last 24 hours:**
```sql
SELECT
    "EventTime",
    "Hostname",
    "Username",
    "Message"
FROM events
WHERE "EventID" = 9194
  AND "Severity" = 4  -- Warning level
  AND "EventTime" > NOW() - INTERVAL '24' HOUR
ORDER BY "EventTime" DESC
```

**3. Custom Rule**
- Name: **Malicious Browser Extension Detected**
- Test: Event matches Event ID 9194 AND Severity is Warning
- Response: Create Offense, Notify, Add to Case

---

## 🛡️ Maintaining the Malicious Extension List

### Hosting Options

#### **Option 1: Public GitHub Repository (Recommended)**
```powershell
# Use actively maintained community lists
-MaliciousExtensionsUrl "https://raw.githubusercontent.com/palant/malicious-extensions-list/main/list.txt"
```

**Pros:**
- ✅ Maintained by security researchers
- ✅ Updated frequently
- ✅ Free and transparent

**Cons:**
- ❌ Requires internet access from endpoints
- ❌ No control over list contents

---

#### **Option 2: Internal GitHub Enterprise / GitLab**
```powershell
-MaliciousExtensionsUrl "https://github.yourcompany.com/raw/security/browser-extensions/main/malicious_list.txt"
```

**Pros:**
- ✅ Full control over list
- ✅ Versioned and auditable
- ✅ Can pull from community lists and customize

**Cons:**
- ⚠️ Requires manual curation/updates

---

#### **Option 3: Internal Web Server**
```powershell
-MaliciousExtensionsUrl "http://security-tools.corp.local/malicious_extensions.txt"
```

Host on IIS, Apache, or nginx:
- ✅ No internet dependency
- ✅ Fast internal network access
- ⚠️ Must implement update process

---

#### **Option 4: File Share (UNC Path)**
```powershell
-MaliciousExtensionsPath "\\fileserver.corp.local\security\malicious_extensions.txt"
```

**Pros:**
- ✅ Simple to update (just edit the file)
- ✅ No HTTP server needed

**Cons:**
- ⚠️ Slower than HTTP for large fleets
- ⚠️ Requires file share permissions

---

### Update Workflow

**Weekly Update Process:**

1. **Pull Latest Community Lists**
```powershell
# Download from trusted sources
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/palant/malicious-extensions-list/main/list.txt" -OutFile "palant_list.txt"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/mallorybowes/chrome-mal-ids/master/current-list.csv" -OutFile "bowes_list.csv"
```

2. **Merge and Deduplicate**
```powershell
# Combine lists
$List1 = Get-Content palant_list.txt | Where-Object { $_ -and $_ -notlike "#*" }
$List2 = (Import-Csv bowes_list.csv).id
$Combined = ($List1 + $List2) | Sort-Object -Unique

# Add header comments
@"
# Malicious Browser Extensions List
# Last Updated: $(Get-Date -Format "yyyy-MM-dd")
# Sources: Palant, Bowes, Internal Research
#
"@ | Set-Content malicious_extensions.txt

$Combined | Add-Content malicious_extensions.txt
```

3. **Review and Approve**
   - Check for false positives
   - Add internal findings
   - Get security team sign-off

4. **Publish to Repository/Server**
```powershell
# Commit to Git
git add malicious_extensions.txt
git commit -m "Update malicious extensions list - $(Get-Date -Format 'yyyy-MM-dd')"
git push origin main
```

5. **Notify Team**
   - Send email with count of new additions
   - Document any major campaign detections

---

### Trusted Sources for Updates

| Source | URL | Update Frequency |
|--------|-----|------------------|
| **Palant's List** | https://github.com/palant/malicious-extensions-list | Weekly |
| **Bowes List** | https://github.com/mallorybowes/chrome-mal-ids | Monthly |
| **Gnyman List** | https://github.com/gnyman/chromium-mal-ids | Monthly |
| **Malwarebytes Blog** | https://www.malwarebytes.com/blog | As incidents occur |
| **The Hacker News** | https://thehackernews.com | Daily |
| **BleepingComputer** | https://www.bleepingcomputer.com | Daily |

---

## ❓ Troubleshooting

### Script Fails with "Access Denied"

**Cause:** Script not running as Administrator (first run only)

**Solution:**
```powershell
# Right-click PowerShell → Run as Administrator
.\extension_audit.ps1
```

After first run, admin rights no longer required (Event Log source exists).

---

### No Extensions Detected

**Check 1: Do users actually have extensions installed?**
```powershell
# Manually check for Chrome extensions
Get-ChildItem "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Extensions" -Directory
```

**Check 2: Are browser paths correct?**
- Chrome: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions`
- Edge: `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Extensions`
- Brave: `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Extensions`
- Firefox: `%APPDATA%\Mozilla\Firefox\Profiles\*\extensions.json`

**Check 3: PowerShell execution policy**
```powershell
Get-ExecutionPolicy
# If Restricted:
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

### Malicious List Download Fails

**Error:** `Failed to download malicious extensions list from <URL>`

**Solution 1: Check network connectivity**
```powershell
Test-NetConnection raw.githubusercontent.com -Port 443
```

**Solution 2: Check proxy settings**
```powershell
# If behind corporate proxy
$Proxy = "http://proxy.corp.local:8080"
[System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy($Proxy)
```

**Solution 3: Use local file instead**
```powershell
.\extension_audit.ps1 -MaliciousExtensionsPath "C:\Scripts\malicious_extensions.txt"
```

---

### Events Not Appearing in Event Viewer

**Check 1: Verify Event Log source exists**
```powershell
[System.Diagnostics.EventLog]::SourceExists("Browser Extension Alert")
# Should return: True
```

**Check 2: Check Application log**
```powershell
Get-EventLog -LogName Application -Source "Browser Extension Alert" -Newest 10
```

**Check 3: Verify script completed successfully**
```powershell
# Run manually and check for errors
.\extension_audit.ps1
```

---

### Scheduled Task Not Running

**Check 1: Task history**
1. Open **Task Scheduler** (`taskschd.msc`)
2. Find task: **Browser Extension Audit**
3. Click **History** tab
4. Look for error codes

**Check 2: Last run result**
```powershell
Get-ScheduledTask -TaskName "Browser Extension Audit" | Get-ScheduledTaskInfo
```

**Common error codes:**
- `0x0`: Success
- `0x1`: Incorrect function / script error
- `0x41301`: Task is currently running
- `0x41303`: Task has not run yet

**Check 3: Test manually**
```powershell
Start-ScheduledTask -TaskName "Browser Extension Audit"
# Then check Event Viewer immediately
```

---

## 🔐 Security Considerations

### Script Integrity

**Verify script hasn't been tampered with:**
```powershell
# Generate hash
Get-FileHash .\extension_audit.ps1 -Algorithm SHA256

# Compare against known-good hash
# Expected: <YOUR_HASH_HERE>
```

**Sign the script (recommended for production):**
```powershell
# Get code signing certificate
$Cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert

# Sign script
Set-AuthenticodeSignature -FilePath .\extension_audit.ps1 -Certificate $Cert

# Verify signature
Get-AuthenticodeSignature .\extension_audit.ps1
```

---

### Malicious List Validation

**Always validate the source of your malicious extension list:**
- ✅ Use HTTPS URLs when possible
- ✅ Pin to specific Git commit hash for reproducibility
- ✅ Review changes before updating production list
- ✅ Maintain internal audit log of list updates

**Example: Pin to specific commit**
```powershell
# Instead of /main/ (always latest)
-MaliciousExtensionsUrl "https://raw.githubusercontent.com/palant/malicious-extensions-list/abc123def456/list.txt"
# Use specific commit hash (/abc123def456/)
```

---

### Privacy Considerations

**This script logs:**
- ✅ Extension IDs (public identifiers)
- ✅ Extension names (public metadata)
- ✅ Windows usernames (already known to IT)
- ✅ Browser types (already known to IT)

**This script does NOT log:**
- ❌ Browsing history
- ❌ Passwords or credentials
- ❌ Cookies or session data
- ❌ Extension settings or user data

**Ensure compliance with:**
- Internal acceptable use policies
- Employee privacy agreements
- Regional privacy regulations (GDPR, CCPA, etc.)

---

## 📚 FAQ

### Q: Does this remove malicious extensions?
**A:** No. This is a **detection and logging tool only**. Remediation must be done manually or via separate tooling.

### Q: How often should I run this script?
**A:** **Daily** is recommended for most organizations. Weekly minimum. Increase to hourly during active incidents.

### Q: Will this impact system performance?
**A:** Minimal. The script typically completes in 5-30 seconds depending on the number of users and extensions. CPU/disk usage is negligible.

### Q: Can I run this on servers?
**A:** Yes, but servers typically don't have browsers installed. Best suited for workstations and VDI environments.

### Q: What happens if the malicious list is empty?
**A:** All extensions will be logged as benign (Information events). No errors will occur.

### Q: Does this work on macOS or Linux?
**A:** No. This is a Windows-only PowerShell script. Browser extension paths are different on macOS/Linux.

### Q: Can I customize the Event ID?
**A:** Not currently. Event ID 9194 is hard-coded. You can modify the script if needed (line 212).

### Q: Firefox extensions have different ID formats. Will this work?
**A:** Yes. Firefox extensions use email-like IDs (`addon@developer.com`) or GUIDs. The script handles both Chromium and Firefox ID formats.

### Q: What if a user has 100+ extensions?
**A:** All will be logged. Each extension gets one event log entry. Event Viewer and SIEMs handle high volumes without issue.

### Q: Can I test this without affecting production?
**A:** Yes. Run manually on a test machine first. Use `-LogName "Test"` to write to a different log. Check Event Viewer before deploying via GPO/scheduled task.

---

## 📄 License

[Choose one: MIT, Apache 2.0, GPL-3.0, or Proprietary]

Example for MIT:
```
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software.
```

---

## 🤝 Contributing

We welcome contributions! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-browser-support`)
3. Commit changes (`git commit -m 'Add Firefox Developer Edition support'`)
4. Push to branch (`git push origin feature/new-browser-support`)
5. Open a Pull Request

**Ideas for contributions:**
- Support for additional browsers (Opera, Vivaldi, etc.)
- Enhanced Firefox add-on detection
- JSON output format option
- CSV export functionality
- Integration examples for additional SIEMs

---

## 📞 Support

**Issues:** Report bugs or request features at [GitHub Issues](https://github.com/yourorg/browser-extension-audit/issues)

**Security vulnerabilities:** Please report privately to security@yourorg.com

**Questions:** Contact your internal security team or open a discussion on GitHub

---

## 🙏 Acknowledgments

This tool builds upon research and lists maintained by:
- [Wladimir Palant](https://github.com/palant/malicious-extensions-list) - Security researcher
- [Mallory Bowes](https://github.com/mallorybowes/chrome-mal-ids) - Extension ID aggregation
- [GitLab Security Team](https://gitlab-com.gitlab.io/gl-security/) - Threat intelligence
- [Malwarebytes Labs](https://www.malwarebytes.com/blog) - Extension research

---

## 📁 Repository Files

### Core Files (Required)

| File | Description | Required |
|------|-------------|----------|
| **extension_audit.ps1** | Main browser extension audit script | ✅ Required |
| **malicious_extensions.txt** | Known malicious extension IDs list | ✅ Required |
| **README.md** | Complete documentation and usage guide | ✅ Recommended |

### Documentation Files (Recommended)

| File | Description | Required |
|------|-------------|----------|
| **DEPLOYMENT_GUIDE.md** | Step-by-step deployment instructions (GPO, SCCM, Intune) | ⭐ Recommended |
| **QUICK_REFERENCE.md** | One-page cheat sheet for security teams | ⭐ Recommended |
| **MALICIOUS_LIST_FORMAT.md** | Guide for maintaining malicious extensions list | ⭐ Recommended |

### Optional/Legacy Files

| File | Description | Required |
|------|-------------|----------|
| **register_sysmon_source.ps1** | Utility to pre-register Event Log source | ❌ **NOT NEEDED** |

**Note on register_sysmon_source.ps1:**
- This is a **legacy utility script** from early development
- The main `extension_audit.ps1` script **automatically creates the Event Log source** on first run
- You do **NOT** need to run this separately
- Kept in repository for reference only

### Personal Setup Guides (For Capstone/Home Lab)

The `for dallin/` folder contains personal setup guides for SIEM integration:
- WAZUH_SETUP_GUIDE.md - Wazuh SIEM setup (free, recommended)
- SPLUNK_FREE_ALTERNATIVE.md - Splunk Free setup (fastest)
- SIEM_COMPARISON.md - Help choosing between SIEMs
- FIREFOX_SUPPORT_EXPLAINED.md - Browser support details
- QUICK_START_CHECKLIST.md - 30-minute demo setup

---

## 📊 Changelog

### Version 2.0 (2026-01-07)
- ✅ Added Firefox support
- ✅ Added Brave browser support
- ✅ Multi-profile scanning (Default, Profile 1, Profile 2, etc.)
- ✅ Added Version field to event logs
- ✅ Added Profile field to event logs
- ✅ Replaced all PowerShell aliases with full cmdlets
- ✅ Comprehensive comment-based help
- ✅ Support for local file paths (`-MaliciousExtensionsPath`)
- ✅ TLS 1.2 enforcement for HTTPS downloads
- ✅ Better error handling for silent execution

### Version 1.0 (Initial)
- ✅ Chrome and Edge support
- ✅ Single profile scanning
- ✅ Basic Event Log output
- ✅ Malicious extension comparison

---

**Ready to deploy? Start with the [Quick Start](#-quick-start) section above!**
