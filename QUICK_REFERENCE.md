# Browser Extension Audit - Quick Reference Card

**Version:** 2.0 | **Last Updated:** 2026-01-07

---

## 🎯 What This Tool Does

Scans all browser extensions (Chrome, Edge, Brave, Firefox) across all user profiles on Windows endpoints and logs findings to Event Viewer. Malicious extensions are flagged by comparing against a known-bad extension ID list.

---

## 📊 Key Information

| Item | Value |
|------|-------|
| **Event Log** | Application (default) |
| **Event Source** | Browser Extension Alert (default) |
| **Event ID** | 9194 |
| **Event Type** | Information (benign) / Warning (malicious) |
| **Script Runtime** | 5-30 seconds (typical) |
| **Admin Required** | First run only (to create Event Log source) |
| **Supported OS** | Windows 7+ / Server 2008 R2+ |
| **PowerShell Version** | 3.0+ |

---

## ⚡ Quick Commands

### Run Script Manually
```powershell
# Basic (uses defaults)
.\extension_audit.ps1

# Custom settings
.\extension_audit.ps1 -LogName "Application" -SourceName "BrowserSec" -MaliciousExtensionsUrl "https://your-url.com/list.txt"

# Use local malicious list file
.\extension_audit.ps1 -MaliciousExtensionsPath "C:\Security\malicious.txt"
```

### Check Event Viewer
```powershell
# Get last 10 extension events
Get-EventLog -LogName Application -Source "Browser Extension Alert" -Newest 10

# Get malicious detections only (Warning events)
Get-EventLog -LogName Application -Source "Browser Extension Alert" -EntryType Warning

# Export to CSV
Get-EventLog -LogName Application -Source "Browser Extension Alert" -Newest 1000 |
    Select-Object TimeGenerated, EntryType, Message |
    Export-Csv "ExtensionAudit.csv" -NoTypeInformation
```

### Verify Scheduled Task
```powershell
# Check if task exists
Get-ScheduledTask -TaskName "Browser Extension Audit"

# Get last run info
Get-ScheduledTask -TaskName "Browser Extension Audit" | Get-ScheduledTaskInfo

# Run task manually
Start-ScheduledTask -TaskName "Browser Extension Audit"

# Check task history
Get-ScheduledTask -TaskName "Browser Extension Audit" |
    Get-ScheduledTaskInfo |
    Select-Object LastRunTime, LastTaskResult
```

---

## 🔍 SIEM Query Examples

### Splunk
```spl
# All extensions scanned today
index=windows EventCode=9194 earliest=-24h
| stats count by ComputerName, ExtensionId, Name

# Malicious extensions detected
index=windows EventCode=9194 Type=Warning
| rex field=Message "ExtensionId: (?<ExtID>[^\r\n]+)"
| rex field=Message "Name: (?<ExtName>[^\r\n]+)"
| table _time, ComputerName, ExtID, ExtName

# Top 10 most common extensions
index=windows EventCode=9194 earliest=-7d
| rex field=Message "Name: (?<ExtName>[^\r\n]+)"
| top 10 ExtName
```

### Microsoft Sentinel (KQL)
```kql
// All malicious detections
Event
| where EventID == 9194 and EventLevelName == "Warning"
| project TimeGenerated, Computer, RenderedDescription
| order by TimeGenerated desc

// Count by computer
Event
| where EventID == 9194 and EventLevelName == "Warning"
| summarize MaliciousCount = count() by Computer
| order by MaliciousCount desc
```

### Windows Event Viewer Filter
```xml
<QueryList>
  <Query Id="0" Path="Application">
    <Select Path="Application">
      *[System[(EventID=9194)]]
      and
      *[System[Level=3]]
    </Select>
  </Query>
</QueryList>
```
*(Paste into Event Viewer → Filter Current Log → XML tab)*

---

## 📋 Event Log Message Format

```
RuleName: -
UtcTime: 2026-01-07 19:30:45.123
Hostname: WORKSTATION01
UserName: john.doe
Browser: Chrome
Profile: Default
ExtensionId: aapbdbdomjkkjkaonfhkkikfgjllcleb
Name: Malicious Extension Name
Version: 1.2.3
Malicious: TRUE
```

### Parse Event Fields (PowerShell)
```powershell
Get-EventLog -LogName Application -Source "Browser Extension Alert" -Newest 100 |
    ForEach-Object {
        $Message = $_.Message
        [PSCustomObject]@{
            Time = $_.TimeGenerated
            Type = $_.EntryType
            Hostname = if ($Message -match 'Hostname: ([^\r\n]+)') { $matches[1] }
            User = if ($Message -match 'UserName: ([^\r\n]+)') { $matches[1] }
            Browser = if ($Message -match 'Browser: ([^\r\n]+)') { $matches[1] }
            ExtensionId = if ($Message -match 'ExtensionId: ([^\r\n]+)') { $matches[1] }
            Name = if ($Message -match 'Name: ([^\r\n]+)') { $matches[1] }
            Malicious = if ($Message -match 'Malicious: ([^\r\n]+)') { $matches[1] }
        }
    } | Export-Csv "ParsedExtensions.csv" -NoTypeInformation
```

---

## 🛡️ Malicious Extensions List Format

**File:** Plain text, one extension ID per line

```txt
# Comment lines start with #
# Blank lines are ignored

# Malicious crypto miners
aapbdbdomjkkjkaonfhkkikfgjllcleb
bcjindcccaagfpapjjmafapmmgkkhgoa

# Data stealers
pkedcjkdefgpdelpbcmbmeomcjbeemfm
```

### Recommended Sources for Updates
- https://github.com/palant/malicious-extensions-list
- https://github.com/mallorybowes/chrome-mal-ids
- https://github.com/gnyman/chromium-mal-ids

### Update Frequency
**Recommended:** Weekly minimum, daily during active campaigns

---

## 🚨 Alert Recommendations

| Severity | Condition | Action |
|----------|-----------|--------|
| **Critical** | 5+ malicious extensions on one system | Immediate investigation, potential compromise |
| **High** | Any malicious extension detected | Create incident ticket, notify user's manager |
| **Medium** | New unknown extension appears on 50+ systems | Review for legitimacy, update list |
| **Low** | Extension inventory baseline change | Document and monitor |

---

## 🔧 Common Troubleshooting

| Issue | Quick Fix |
|-------|-----------|
| **No events appearing** | Run script manually as admin, verify Event Log source exists |
| **Scheduled task not running** | Check trigger, verify script path accessible, check Last Run Result code |
| **Download fails** | Use `-MaliciousExtensionsPath` with local file instead of URL |
| **SIEM not collecting** | Verify Event ID 9194 in SIEM agent config, check agent is running |
| **Script errors** | Check Windows Event Log (Application) for PowerShell errors |

### Last Run Result Codes
- `0x0` = Success
- `0x1` = Script error (check logs)
- `0x41301` = Task currently running
- `0x41303` = Task has not run yet

---

## 📞 Incident Response Workflow

When malicious extension detected (Event Type = Warning):

1. **Identify affected user/system**
   - Check Hostname and UserName fields in event

2. **Isolate if critical**
   - If multiple malicious extensions or known C2 tool → isolate system

3. **Extract extension details**
   - ExtensionId: Unique identifier for tracking
   - Name: User-visible name (may be misleading)
   - Version: Helps identify specific campaign

4. **Research the extension**
   - Search ExtensionId online for threat intel
   - Check if associated with known campaign
   - Review malicious list source for context

5. **Remove extension**
   - Guide user to remove: `chrome://extensions` or `about:addons` (Firefox)
   - Or remove via script:
   ```powershell
   # Chrome/Edge example
   $ExtId = "aapbdbdomjkkjkaonfhkkikfgjllcleb"
   $UserProfile = "C:\Users\john.doe"
   Remove-Item "$UserProfile\AppData\Local\Google\Chrome\User Data\Default\Extensions\$ExtId" -Recurse -Force
   ```

6. **Verify removal**
   - Re-run audit script
   - Check for persistence mechanisms (registry, scheduled tasks)

7. **Document incident**
   - Add to incident tracking system
   - Note TTPs, IOCs, remediation steps

8. **Update defenses**
   - If new malicious extension → add to list
   - Review if browser policy enforcement needed

---

## 📁 File Locations Reference

### Script Components
```
C:\Scripts\
├── extension_audit.ps1           # Main script
├── malicious_extensions.txt      # Malicious ID list (optional local copy)
└── README.md                      # Full documentation
```

### Browser Extension Paths
```
Chrome:    %LOCALAPPDATA%\Google\Chrome\User Data\{Profile}\Extensions\{ExtensionID}\{Version}\
Edge:      %LOCALAPPDATA%\Microsoft\Edge\User Data\{Profile}\Extensions\{ExtensionID}\{Version}\
Brave:     %LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\{Profile}\Extensions\{ExtensionID}\{Version}\
Firefox:   %APPDATA%\Mozilla\Firefox\Profiles\{ProfileID}\extensions.json
```

### Event Logs
```
Event Viewer: eventvwr.msc
Path: Windows Logs → Application
Filter: Event ID = 9194, Source = "Browser Extension Alert"

Export: wevtutil epl Application C:\Logs\Application.evtx /q:"*[System[(EventID=9194)]]"
```

---

## 🔗 Quick Links

- **Full Documentation:** README.md
- **Deployment Guide:** DEPLOYMENT_GUIDE.md
- **Script Parameters:** `Get-Help .\extension_audit.ps1 -Full`
- **Malicious List Sample:** malicious_extensions.txt

---

## 📊 Metrics to Track

### Weekly
- Total extensions scanned
- Unique extensions discovered
- Malicious detections (count and IDs)
- Systems reporting vs. total fleet

### Monthly
- Extension install trends (new/removed)
- Top 10 most common extensions
- Malicious extension families detected
- Coverage percentage (reporting systems / total systems)

### Quarterly
- False positive rate
- Incident response times
- Policy enforcement effectiveness
- User awareness trends

---

## ✅ Pre-Deployment Checklist

- [ ] Script tested on representative systems (Win 10, Win 11, Server)
- [ ] Event Log source created on test machine
- [ ] SIEM confirmed receiving Event ID 9194
- [ ] Malicious extensions list accessible from endpoints
- [ ] GPO/scheduled task configured and linked
- [ ] Alert rules configured in SIEM
- [ ] Incident response workflow documented
- [ ] Security team trained on event log format
- [ ] Remediation procedures documented

---

**Need more details?** See full documentation in [README.md](README.md)
