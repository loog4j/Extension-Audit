# Browser Extension Audit Tool

A PowerShell script that scans browser extensions across all user profiles on a Windows machine and logs what it finds to Windows Event Viewer. It compares each extension against a list of known-malicious extension IDs and flags matches as warnings, so your SIEM can pick them up.

Supports Chrome, Edge, Brave, and Firefox. Runs silently — designed to be dropped into a scheduled task or GPO.

## How it works

1. Loads a list of known-malicious extension IDs (from a URL or local file)
2. Enumerates all user profiles on the system via WMI
3. For each user, walks the extension directories for each supported browser
4. Reads each extension's `manifest.json` to pull its name and version
5. Checks the extension ID against the malicious list
6. Writes one Event Log entry per extension found (Event ID **9191**)
   - **Information** = benign
   - **Warning** = malicious match

## Quick start

```powershell
# First run — needs to be run as Administrator to register the Event Log source
.\Scripts\extension_audit.ps1

# After that, admin isn't required
.\Scripts\extension_audit.ps1
```

Then open Event Viewer (`eventvwr.msc`), go to **Windows Logs > Application**, and filter on Event ID **9191**.

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-LogName` | `Application` | Which Windows Event Log to write to |
| `-SourceName` | `Browser Extension Alert` | Event source name |
| `-Match` | *(none)* | Regex filter — only log extensions whose name matches |
| `-MaliciousExtensionsUrl` | GitHub raw URL to `ExtensionIDs/malicious_extensions.txt` in this repo | URL to download the malicious ID list from |
| `-MaliciousExtensionsPath` | *(none)* | Local file or UNC path to malicious list (skips URL download) |

### Examples

```powershell
# Scan everything with defaults
.\Scripts\extension_audit.ps1

# Only log extensions with "adblock" in the name
.\Scripts\extension_audit.ps1 -Match "adblock"

# Use a local copy of the malicious list
.\Scripts\extension_audit.ps1 -MaliciousExtensionsPath "C:\Security\malicious_extensions.txt"

# Use a file share
.\Scripts\extension_audit.ps1 -MaliciousExtensionsPath "\\fileserver\security\malicious_extensions.txt"

# Custom event source
.\Scripts\extension_audit.ps1 -SourceName "BrowserSecurity"
```

## Requirements

- **OS:** Windows 7+ / Server 2008 R2+
- **PowerShell:** 3.0+
- **Permissions:** Administrator on first run only (to create the Event Log source). After that, standard user is fine. Scheduled tasks running as SYSTEM won't have this issue.
- **Network:** HTTPS access to the malicious list URL, unless you use `-MaliciousExtensionsPath`

## Event log format

Each extension produces one event with this message body:

```
RuleName: -
UtcTime: 2026-01-07 19:30:45.123
Hostname: DESKTOP-PC01
UserName: john.doe
Browser: Chrome
Profile: Default
ExtensionId: aapbdbdomjkkjkaonfhkkikfgjllcleb
Name: Some Extension
Version: 1.2.3
Malicious: TRUE
```

| Field | Notes |
|-------|-------|
| `RuleName` | Reserved, always `-` |
| `UtcTime` | When the extension was scanned |
| `Hostname` | Machine name |
| `UserName` | Windows profile name (from the folder path, not the SID) |
| `Browser` | Chrome, Edge, Brave, or Firefox |
| `Profile` | Browser profile folder name (Default, Profile 1, etc.) |
| `ExtensionId` | Chromium: 32 lowercase letters. Firefox: email-style or GUID |
| `Malicious` | `TRUE` if the ID matched the malicious list, `FALSE` otherwise |

## Deploying as a scheduled task

### Single machine (testing)

```powershell
$Action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File C:\Scripts\extension_audit.ps1"
$Trigger = New-ScheduledTaskTrigger -Daily -At 2:00AM
$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Register-ScheduledTask -TaskName "Browser Extension Audit" `
    -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings `
    -Description "Daily browser extension audit"
```

### Domain-wide (GPO)

1. Place the script in SYSVOL (e.g., `\\domain.com\SYSVOL\domain.com\scripts\extension_audit.ps1`)
2. In GPMC, go to **Computer Configuration > Preferences > Control Panel Settings > Scheduled Tasks**
3. Create a scheduled task running as `NT AUTHORITY\SYSTEM` with highest privileges
4. Action: `powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File "\\domain.com\SYSVOL\domain.com\scripts\extension_audit.ps1"`
5. Trigger: Daily at your preferred time
6. Link the GPO to workstation OUs

### Intune

Use a Proactive Remediation package:
- Detection script: `exit 1` (always triggers remediation)
- Remediation script: paste the contents of `extension_audit.ps1`
- Run in 64-bit PowerShell as SYSTEM
- Schedule: Daily

## SIEM integration

Forward Event ID 9191 from the Application log. Filter on `EntryType = Warning` for malicious hits only.

### Splunk

```ini
# inputs.conf
[WinEventLog://Application]
disabled = 0
index = windows
sourcetype = WinEventLog:Application
whitelist = 9191
```

```spl
# Malicious detections
index=windows sourcetype="WinEventLog:Application" EventCode=9191 Type=Warning
| rex field=Message "ExtensionId: (?<ExtID>[^\r\n]+)"
| rex field=Message "Name: (?<ExtName>[^\r\n]+)"
| rex field=Message "Hostname: (?<Host>[^\r\n]+)"
| rex field=Message "UserName: (?<User>[^\r\n]+)"
| table _time, Host, User, ExtID, ExtName
| sort -_time
```

### Microsoft Sentinel

```kql
Event
| where EventID == 9191 and EventLevelName == "Warning"
| project TimeGenerated, Computer, RenderedDescription
| order by TimeGenerated desc
```

### Elastic (Winlogbeat)

```yaml
winlogbeat.event_logs:
  - name: Application
    event_id: 9191
```

## Malicious extensions list

The file at `ExtensionIDs/malicious_extensions.txt` contains 534 known-malicious extension IDs (513 Chromium, 21 Firefox). Format is one extension ID per line, `#` for comments, blank lines ignored.

You should keep this list up to date. Good sources:

| Source | URL |
|--------|-----|
| Palant's list | Archived on GitHub; moved to Codeberg (check palant.info for current link) |
| Bowes list | https://github.com/mallorybowes/chrome-mal-ids |
| nicoleahmed list | https://github.com/nicoleahmed/malicious-extensions-list |

You can host the list wherever makes sense for your environment — public GitHub, internal Git, a web server, or a file share. Use `-MaliciousExtensionsUrl` or `-MaliciousExtensionsPath` accordingly.

## Repo structure

```
Scripts/
  extension_audit.ps1           # The main script
  register_sysmon_source.ps1    # Optional utility to pre-register the Event Log source
ExtensionIDs/
  malicious_extensions.txt      # Starter list of known-malicious extension IDs
Documentation/
  DEPLOYMENT_GUIDE.md           # Detailed deployment walkthrough
  MALICIOUS_LIST_FORMAT.md      # Guide for maintaining the malicious list
  CONTRIBUTING.md
  SECURITY.md
  GITHUB_SETUP_INSTRUCTIONS.md
QUICK_REFERENCE.md              # One-page cheat sheet
```

`register_sysmon_source.ps1` is not required — the main script creates the Event Log source automatically on first run. It's there if you want to pre-register the source separately before deploying.

## Troubleshooting

**Script fails with "Access Denied":** Run as Administrator. This is only needed on the first run to create the Event Log source. After that, standard user works.

**No extensions found:** Verify the browser extension directories actually exist — `Get-ChildItem "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Extensions" -Directory`

**Malicious list download fails:** Check network access to the URL, or switch to a local file with `-MaliciousExtensionsPath`.

**Events not showing up in Event Viewer:** Confirm the source exists: `[System.Diagnostics.EventLog]::SourceExists("Browser Extension Alert")`

## FAQ

**Does this remove malicious extensions?** No. Detection and logging only.

**Will it slow down machines?** No. Runs in 5-30 seconds, minimal CPU/disk.

**Does it work on macOS or Linux?** No. Windows only — the extension paths and Event Log APIs are Windows-specific.

**Can I change the Event ID?** Not via parameter. It's hardcoded to 9191 in the script. Edit the `Write-EventLog` call if you need something different.

**What about Firefox extension IDs?** Firefox uses email-style IDs (`addon@developer.com`) or GUIDs, not the 32-letter Chromium format. The script handles both.

## License

MIT — see [LICENSE](LICENSE).
