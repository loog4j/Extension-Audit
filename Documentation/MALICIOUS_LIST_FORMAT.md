# Malicious Extensions List - File Format Guide

This document explains how to create and maintain the malicious browser extensions list used by the audit script.

---

## 📄 File Format Specification

### Basic Requirements

| Property | Value |
|----------|-------|
| **File Type** | Plain text (`.txt`) |
| **Encoding** | UTF-8 or ASCII |
| **Line Endings** | Windows (CRLF) or Unix (LF) - both supported |
| **File Extension** | `.txt` (required) |
| **Format** | One extension ID per line |

---

## ✅ Valid Format Examples

### Example 1: Minimal (No Comments)
```txt
aapbdbdomjkkjkaonfhkkikfgjllcleb
bcjindcccaagfpapjjmafapmmgkkhgoa
pkedcjkdefgpdelpbcmbmeomcjbeemfm
cfhdojbkjhnklbpkdaibdccddilifddb
lkmjhfbnogcngnbpgdpkmlplcblpfhhb
```

---

### Example 2: With Comments (Recommended)
```txt
# Malicious Browser Extensions List
# Last Updated: 2026-01-07
# Maintained by: Security Team

# Cryptomining extensions discovered in Q4 2024
aapbdbdomjkkjkaonfhkkikfgjllcleb  # CryptoMiner Pro - discovered 2024-12-15
bcjindcccaagfpapjjmafapmmgkkhgoa  # HiddenMiner - campaign "ShadyPanda"

# Credential stealers from January 2025 campaign
pkedcjkdefgpdelpbcmbmeomcjbeemfm  # FakeVPN - steals passwords
cfhdojbkjhnklbpkdaibdccddilifddb  # SearchHelper - keylogger

# Adware/malicious injectors
lkmjhfbnogcngnbpgdpkmlplcblpfhhb  # AdInjector - injects ads on all pages
```

---

### Example 3: Organized by Category
```txt
# ============================================================================
# MALICIOUS BROWSER EXTENSIONS LIST
# ============================================================================
# Organization: YourCompany InfoSec Team
# Last Updated: 2026-01-07
# Update Frequency: Weekly
# Sources: Palant, Bowes, Internal Research
# ============================================================================

# ----------------------------------------------------------------------------
# CRYPTOMINERS (Priority: High)
# ----------------------------------------------------------------------------
# These extensions use system resources to mine cryptocurrency
# Impact: Performance degradation, increased power consumption

aapbdbdomjkkjkaonfhkkikfgjllcleb  # CryptoMiner Pro - Detected: 2024-12-15
bcjindcccaagfpapjjmafapmmgkkhgoa  # HiddenMiner - Campaign: ShadyPanda
mhjfbmdgcfjbbpaeojofohoefgiehjai  # MineInBackground - Monero miner

# ----------------------------------------------------------------------------
# CREDENTIAL STEALERS (Priority: Critical)
# ----------------------------------------------------------------------------
# These extensions harvest usernames, passwords, and session cookies
# Impact: Account compromise, data breach

pkedcjkdefgpdelpbcmbmeomcjbeemfm  # FakeVPN - CVE-2024-XXXXX
cfhdojbkjhnklbpkdaibdccddilifddb  # SearchHelper - Keylogger component
lkmjhfbnogcngnbpgdpkmlplcblpfhhb  # Password Manager Fake - Exfiltrates to C2

# ----------------------------------------------------------------------------
# ADWARE / MALICIOUS INJECTORS (Priority: Medium)
# ----------------------------------------------------------------------------
# These extensions inject unwanted advertisements or modify web content
# Impact: Privacy violation, potential malvertising

nlbjncdgjeocebhnmkbbbdekmmmcbfjd  # AdInjector Pro
ofjgnhihlklpobkaloamkankaaoclfjh  # SearchRedirect - Hijacks search results

# ----------------------------------------------------------------------------
# DATA EXFILTRATION / SPYWARE (Priority: Critical)
# ----------------------------------------------------------------------------
# These extensions collect and transmit browsing data without consent
# Impact: Privacy violation, corporate espionage risk

lgjdgmdbfhobkdbcjnpnlmhnplnidkkp  # Autoskip for Youtube - Sleeper agent (activated 2024-06)
chmfnmjfghjpdamlofhlonnnnokkpbao  # Soundboost - Turned malicious 2024-07

# End of list
```

---

## 🚫 Invalid Formats (Will NOT Work)

### ❌ CSV Format
```csv
ExtensionID,Name,Category,DateAdded
aapbdbdomjkkjkaonfhkkikfgjllcleb,CryptoMiner,Miner,2024-12-15
bcjindcccaagfpapjjmafapmmgkkhgoa,HiddenMiner,Miner,2024-12-20
```
**Why it fails:** Script expects one ID per line, not CSV columns.

---

### ❌ JSON Format
```json
{
  "malicious_extensions": [
    {
      "id": "aapbdbdomjkkjkaonfhkkikfgjllcleb",
      "name": "CryptoMiner",
      "category": "Miner"
    }
  ]
}
```
**Why it fails:** Script parses plain text, not JSON.

---

### ❌ XML Format
```xml
<extensions>
  <extension id="aapbdbdomjkkjkaonfhkkikfgjllcleb" name="CryptoMiner"/>
</extensions>
```
**Why it fails:** Script doesn't parse XML.

---

### ❌ Multiple IDs Per Line
```txt
aapbdbdomjkkjkaonfhkkikfgjllcleb, bcjindcccaagfpapjjmafapmmgkkhgoa
pkedcjkdefgpdelpbcmbmeomcjbeemfm, cfhdojbkjhnklbpkdaibdccddilifddb
```
**Why it fails:** Each line is treated as a single extension ID (commas included).

---

## 📝 Formatting Rules

### Rule 1: One Extension ID Per Line
✅ **Correct:**
```txt
aapbdbdomjkkjkaonfhkkikfgjllcleb
bcjindcccaagfpapjjmafapmmgkkhgoa
```

❌ **Incorrect:**
```txt
aapbdbdomjkkjkaonfhkkikfgjllcleb bcjindcccaagfpapjjmafapmmgkkhgoa
```

---

### Rule 2: Comments Use # Symbol
✅ **Correct:**
```txt
# This is a comment
aapbdbdomjkkjkaonfhkkikfgjllcleb  # Inline comment also works
```

❌ **Incorrect:**
```txt
// This won't work - double slashes not supported
aapbdbdomjkkjkaonfhkkikfgjllcleb /* No C-style comments */
```

---

### Rule 3: Blank Lines Are Ignored
✅ **Correct:**
```txt
aapbdbdomjkkjkaonfhkkikfgjllcleb

bcjindcccaagfpapjjmafapmmgkkhgoa


pkedcjkdefgpdelpbcmbmeomcjbeemfm
```
*(Blank lines for readability - completely fine)*

---

### Rule 4: Whitespace is Trimmed
✅ **All of these are equivalent:**
```txt
aapbdbdomjkkjkaonfhkkikfgjllcleb
  aapbdbdomjkkjkaonfhkkikfgjllcleb
aapbdbdomjkkjkaonfhkkikfgjllcleb
   aapbdbdomjkkjkaonfhkkikfgjllcleb
```
*(Leading and trailing spaces removed automatically)*

---

### Rule 5: Extension IDs are Case-Sensitive
✅ **Correct:**
```txt
aapbdbdomjkkjkaonfhkkikfgjllcleb  # Lowercase (standard Chrome format)
```

⚠️ **May not match:**
```txt
AAPBDBDOMJKKJKAONFHKKIKFGJLLCLEB  # Uppercase - won't match if actual ID is lowercase
```

**Best practice:** Always use lowercase for Chromium extension IDs (Chrome/Edge/Brave standard format).

---

## 🔍 Extension ID Formats by Browser

### Chrome / Edge / Brave (Chromium)
- **Format:** 32-character lowercase hexadecimal string
- **Character set:** `a-z`, `0-9` only
- **Example:** `aapbdbdomjkkjkaonfhkkikfgjllcleb`

**Where to find:**
1. Open browser
2. Navigate to `chrome://extensions` (or `edge://extensions`)
3. Enable "Developer mode"
4. Extension ID shown below each extension name

---

### Firefox
- **Format:** Email-like or GUID
- **Examples:**
  - `addon@developer.mozilla.org` (email format)
  - `{12345678-1234-1234-1234-123456789012}` (GUID format)

**Where to find:**
1. Navigate to `about:debugging#/runtime/this-firefox`
2. Extension UUID shown under "Internal UUID"

OR

Check `extensions.json` in profile directory:
```
%APPDATA%\Mozilla\Firefox\Profiles\{profile}\extensions.json
```

---

## 🛠️ Creating Your List

### Step 1: Start with Community Lists

Download from trusted sources:
```powershell
# Palant's list (Chrome/Edge)
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/palant/malicious-extensions-list/main/list.txt" -OutFile "palant_list.txt"

# Bowes' list (Chrome)
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/mallorybowes/chrome-mal-ids/master/current-list.csv" -OutFile "bowes_list.csv"
```

---

### Step 2: Merge and Deduplicate

```powershell
# Read Palant's list (already plain text)
$PalantList = Get-Content palant_list.txt | Where-Object { $_ -and $_ -notlike "#*" }

# Parse Bowes' CSV (extract ID column)
$BowesList = (Import-Csv bowes_list.csv).id

# Combine and remove duplicates
$MergedList = ($PalantList + $BowesList) | Sort-Object -Unique

# Save to new file
$MergedList | Set-Content "malicious_extensions.txt"
```

---

### Step 3: Add Header and Comments

```powershell
# Create header
$Header = @"
# Malicious Browser Extensions List
# Organization: $(Read-Host "Organization name")
# Last Updated: $(Get-Date -Format "yyyy-MM-dd")
# Total Entries: $($MergedList.Count)
#
# Sources:
# - https://github.com/palant/malicious-extensions-list
# - https://github.com/mallorybowes/chrome-mal-ids
# - Internal security research
#
# Update this list weekly from trusted sources
# ============================================================================

"@

# Combine header with list
$Header | Set-Content "malicious_extensions.txt"
$MergedList | Add-Content "malicious_extensions.txt"
```

---

### Step 4: Add Internal Findings

When your security team discovers new malicious extensions:

```powershell
# Append new entries
$NewEntry = @"

# ============================================================================
# INTERNAL DISCOVERIES
# ============================================================================

# Discovered during incident #INC-2026-001 on 2026-01-07
# Extension: FakeProductivityTool
# Impact: Credential theft, session hijacking
# Analyst: J. Smith
xyz123abc456def789ghi012jkl345mn  # FakeProductivityTool v1.2.3

"@

$NewEntry | Add-Content "malicious_extensions.txt"
```

---

## 📤 Hosting Your List

### Option 1: GitHub Repository
```bash
# Create repo
git init
git add malicious_extensions.txt
git commit -m "Initial malicious extensions list"
git remote add origin https://github.com/yourorg/security-lists.git
git push -u origin main

# Use in script:
# -MaliciousExtensionsUrl "https://raw.githubusercontent.com/yourorg/security-lists/main/malicious_extensions.txt"
```

---

### Option 2: Internal Web Server
```powershell
# Copy to web server document root
Copy-Item malicious_extensions.txt -Destination "C:\inetpub\wwwroot\security\"

# Test access
Invoke-WebRequest -Uri "http://webserver.corp.local/security/malicious_extensions.txt"

# Use in script:
# -MaliciousExtensionsUrl "http://webserver.corp.local/security/malicious_extensions.txt"
```

---

### Option 3: File Share
```powershell
# Copy to network share
Copy-Item malicious_extensions.txt -Destination "\\fileserver\security\malicious_extensions.txt"

# Set permissions (read-only for Domain Computers)
icacls "\\fileserver\security\malicious_extensions.txt" /grant "Domain Computers:(R)"

# Use in script:
# -MaliciousExtensionsPath "\\fileserver\security\malicious_extensions.txt"
```

---

## ✅ Validation Checklist

Before deploying your malicious list, verify:

- [ ] File is plain text (.txt extension)
- [ ] One extension ID per line (no commas, semicolons, etc.)
- [ ] All extension IDs are 32 characters (Chromium) or valid Firefox format
- [ ] Comments use # symbol only
- [ ] No CSV headers, JSON, or XML formatting
- [ ] File is accessible from endpoint systems
- [ ] File encoding is UTF-8 or ASCII (not UTF-16)
- [ ] Line endings are consistent (CRLF or LF, not mixed)

**Test your list:**
```powershell
# Download and parse locally
$List = (Get-Content malicious_extensions.txt) -split "`n" |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -ne "" -and $_ -notlike "#*" }

# Verify count
Write-Host "Total malicious extension IDs: $($List.Count)"

# Check for valid format (Chromium IDs should be 32 chars)
$InvalidIds = $List | Where-Object { $_.Length -ne 32 -and $_ -notmatch '@' -and $_ -notmatch '^\{' }
if ($InvalidIds) {
    Write-Warning "Found potentially invalid IDs:"
    $InvalidIds | ForEach-Object { Write-Warning $_ }
}
```

---

## 🔄 Update Workflow

**Weekly Update Process:**

1. **Pull latest community lists** (Monday)
   ```powershell
   .\update_malicious_list.ps1  # Your custom update script
   ```

2. **Review changes** (Monday-Tuesday)
   - Compare new IDs against previous week
   - Research any unknown extensions
   - Check for false positives

3. **Approve and publish** (Wednesday)
   - Security team sign-off
   - Commit to Git repository or update file share

4. **Monitor detections** (Thursday-Friday)
   - Check SIEM for new malicious hits
   - Investigate any detections
   - Update incident response procedures if needed

---

## 📞 Support

Questions about list format? Check:
- **Full Documentation:** README.md
- **Script Help:** `Get-Help .\extension_audit.ps1 -Full`
- **Example List:** malicious_extensions.txt (included)

---

**Ready to create your list?** Use the [Example 3](#example-3-organized-by-category) template above as a starting point.
