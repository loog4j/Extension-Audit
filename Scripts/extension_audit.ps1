<#
.SYNOPSIS
    Audits browser extensions and detects known malicious extensions.

.DESCRIPTION
    Scans Chrome, Edge, Firefox, and Brave extensions across all user profiles on the system.
    Compares discovered extensions against a known malicious extensions list and logs findings
    to Windows Event Log in Sysmon-compatible format for SIEM integration.

    Designed for silent execution via GPO, scheduled tasks, or configuration management tools.

.PARAMETER LogName
    Windows Event Log name where events will be written.
    Default: "Application"

.PARAMETER SourceName
    Event source name for log entries. Will be created if it doesn't exist.
    Default: "Browser Extension Alert"

.PARAMETER Match
    Optional filter to scan only extensions matching this name pattern (regex supported).
    If omitted, all extensions are scanned.

.PARAMETER MaliciousExtensionsUrl
    URL to download the malicious extensions list (plain text, one ID per line).
    Supports both HTTPS (external) and HTTP (internal network).
    Default: "https://raw.githubusercontent.com/yourdomain/malicious-extensions/main/extensions.txt"

.PARAMETER MaliciousExtensionsPath
    Alternative to URL: Local file path or UNC path to malicious extensions list.
    Use this for offline environments or file share hosting.
    Example: "\\fileserver\security\malicious_extensions.txt"

.EXAMPLE
    .\extension_audit.ps1
    Scans all extensions using default settings and logs to Application event log.

.EXAMPLE
    .\extension_audit.ps1 -Match "adblock"
    Scans only extensions with "adblock" in the name.

.EXAMPLE
    .\extension_audit.ps1 -MaliciousExtensionsPath "C:\Security\malicious_list.txt"
    Uses local file instead of downloading from URL.

.EXAMPLE
    .\extension_audit.ps1 -LogName "Application" -SourceName "BrowserSecurity"
    Customizes Event Log name and source.

.NOTES
    Requires:     Administrator privileges (for Event Log source creation on first run)
    Version:      2.0
    Event ID:     9194 (Information for benign, Warning for malicious)

    Malicious Extensions List Format:
        - Plain text file, one extension ID per line
        - Lines starting with # are treated as comments
        - Blank lines are ignored
        - Extension IDs are 32-character lowercase hex strings

    Example:
        # Malicious crypto miners
        aapbdbdomjkkjkaonfhkkikfgjllcleb
        bcjindcccaagfpapjjmafapmmgkkhgoa

    SIEM Integration:
        - Query Event ID 9194 from specified log
        - Filter EntryType=Warning for malicious detections
        - Parse message field for structured data

.LINK
    https://github.com/yourdomain/browser-extension-audit
#>

#Requires -Version 3.0
#Requires -RunAsAdministrator

param(
    [ValidateSet('Application','Security','System')]
    [string]$LogName = "Application",

    [ValidateNotNullOrEmpty()]
    [string]$SourceName = "Browser Extension Alert",

    [string]$Match = $null,

    [string]$MaliciousExtensionsUrl = "https://github.com/loog4j/Extension-Audit/blob/main/ExtensionIDs/malicious_extensions.txt",

    [string]$MaliciousExtensionsPath = $null
)

# Converts PSCustomObject from ConvertFrom-Json to hashtable for consistent data handling
# PowerShell 3.0+ returns PSCustomObject, but hashtables are easier to work with
function Convert-Hashtable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [psobject]$Object
    )

    [hashtable]$Hashtable = @{}
    $Object.PSObject.Properties | Where-Object { ![string]::IsNullOrEmpty($_.Value) } | ForEach-Object {
        # Sanitize property names: replace spaces with underscores, remove special characters
        $Hashtable[($_.Name -replace '\s','_' -replace '\W',$null)] = $_.Value
    }
    return $Hashtable
}

# Deserializes JSON string to hashtable
# Handles PowerShell 2.0 legacy systems using JavaScriptSerializer fallback
function Convert-Json {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$String
    )

    if ($PSVersionTable.PSVersion -lt [version]"3.0") {
        # PowerShell 2.0 fallback for Windows 7/Server 2008 R2
        return $Script:Serializer.DeserializeObject($String)
    } else {
        $Object = $String | ConvertFrom-Json
        if ($Object) {
            return Convert-Hashtable $Object
        }
    }
}

# Serializes hashtable array to JSON string
function Write-Json {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [hashtable[]]$Hashtable
    )

    if ($PSVersionTable.PSVersion -lt [version]"3.0") {
        return $Script:Serializer.Serialize($Hashtable)
    } else {
        return ConvertTo-Json $Hashtable -Depth 2 -Compress
    }
}

# Downloads malicious extension list from remote URL
# Returns: Array of extension IDs (32-character hex strings)
# Format: One ID per line, # for comments, blank lines ignored
function Get-MaliciousExtensionList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Url
    )

    try {
        # Ensure TLS 1.2 for HTTPS connections
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

        $WebClient = New-Object System.Net.WebClient
        [string]$Content = $WebClient.DownloadString($Url)

        # Parse list: one extension ID per line, ignore comments (#) and blank lines
        [string[]]$List = $Content -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" -and $_ -notlike "#*" }

        return $List
    } catch {
        Write-Warning "Failed to download malicious extensions list from $Url : $_"
        return @()
    }
}

# Writes extension discovery to Windows Event Log in Sysmon-compatible format
# Warning EntryType used for malicious extensions, Information for benign
function Write-ExtensionEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Data,

        [Parameter(Mandatory=$true)]
        [string]$LogName,

        [Parameter(Mandatory=$true)]
        [string]$SourceName,

        [bool]$IsMalicious = $false
    )

    [string]$UtcTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.fff")
    [string]$EntryType = if ($IsMalicious) { "Warning" } else { "Information" }
    [string]$MaliciousStatus = if ($IsMalicious) { "TRUE" } else { "FALSE" }

    # Format matches Sysmon Event structure for consistency with existing security tooling
    # Key-value pairs on separate lines for easy Event Viewer filtering and SIEM parsing
    [string]$Message = @"
RuleName: -
UtcTime: $UtcTime
Hostname: $($Data.Hostname)
UserName: $($Data.UserName)
Browser: $($Data.Browser)
Profile: $($Data.Profile)
ExtensionId: $($Data.ExtensionId)
Name: $($Data.Name)
Version: $($Data.Version)
Malicious: $MaliciousStatus
"@

    try {
        # Event ID 9194 chosen to avoid conflicts with common Microsoft event IDs
        # and provide unique identifier for SIEM correlation
        Write-EventLog -LogName $LogName -Source $SourceName -EntryType $EntryType -EventId 9194 -Message $Message -ErrorAction Stop
    } catch {
        # Silent failure - don't disrupt script execution if event log write fails
        Write-Warning "Failed to write event log entry: $_"
    }
}

# Main function: Enumerates browser extensions across all user profiles
function Get-BrowserExtension {
    [CmdletBinding()]
    param(
        [string]$Match,

        [Parameter(Mandatory=$true)]
        [string]$LogName,

        [Parameter(Mandatory=$true)]
        [string]$SourceName,

        [Parameter(Mandatory=$true)]
        [string[]]$MaliciousList
    )

    # Query only domain/local user profiles (S-1-5-21-*), excluding system accounts, LocalService, NetworkService
    [string]$Query = "SELECT * FROM Win32_UserProfile WHERE sid LIKE 'S-1-5-21%'"

    # Extract extension name from messages.json localization files
    # Pattern matches: "extName": { "message": "Extension Name Here" }
    [string]$NameRegex = '(?<="extName":\s{.*"message":\s).+'

    [string]$Hostname = $env:COMPUTERNAME
    [int]$Count = 0
    [int]$MaliciousCount = 0

    # Define browser paths - Chromium-based browsers share same extension structure
    $Browsers = @{
        'Chrome' = @{
            Path = 'Google\Chrome\User Data'
            Type = 'Chromium'
        }
        'Edge' = @{
            Path = 'Microsoft\Edge\User Data'
            Type = 'Chromium'
        }
        'Brave' = @{
            Path = 'BraveSoftware\Brave-Browser\User Data'
            Type = 'Chromium'
        }
        'Firefox' = @{
            Path = 'Mozilla\Firefox\Profiles'
            Type = 'Firefox'
        }
    }

    foreach ($User in (Get-WmiObject -Query $Query)) {
        [string]$UserName = $User.LocalPath | Split-Path -Leaf

        foreach ($BrowserName in $Browsers.Keys) {
            $BrowserInfo = $Browsers[$BrowserName]

            if ($BrowserInfo.Type -eq 'Chromium') {
                # Chromium-based browsers: Chrome, Edge, Brave
                # Structure: %LOCALAPPDATA%\BrowserPath\Default\Extensions\{ExtensionId}\{Version}\manifest.json
                # Also check other profiles: Profile 1, Profile 2, etc.

                [string]$BrowserRoot = Join-Path $User.LocalPath "AppData\Local\$($BrowserInfo.Path)"

                if (-not (Test-Path $BrowserRoot -PathType Container)) {
                    continue
                }

                # Scan Default profile and numbered profiles (Profile 1, Profile 2, etc.)
                $ProfileDirs = Get-ChildItem $BrowserRoot -Directory | Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' }

                foreach ($ProfileDir in $ProfileDirs) {
                    [string]$ExtRoot = Join-Path $ProfileDir.FullName "Extensions"

                    if (-not (Test-Path $ExtRoot -PathType Container)) {
                        continue
                    }

                    [string]$ProfileName = $ProfileDir.Name

                    # Skip 'Temp' folder which contains incomplete/downloading extensions
                    foreach ($ExtFolder in (Get-ChildItem $ExtRoot | Where-Object { $_.Name -ne 'Temp' })) {

                        # Each extension ID folder contains version subfolders (e.g., 1.0.0_0)
                        # Scan all versions as multiple may exist during updates
                        foreach ($ExtSubfolder in (Get-ChildItem $ExtFolder.FullName -ErrorAction SilentlyContinue)) {

                            [string]$ManifestPath = Join-Path $ExtSubfolder.FullName "manifest.json"

                            if (-not (Test-Path $ManifestPath -PathType Leaf)) {
                                continue
                            }

                            try {
                                [string]$Manifest = Get-Content $ManifestPath -Raw -ErrorAction Stop

                                if (-not $Manifest) {
                                    continue
                                }

                                foreach ($Ext in (Convert-Json $Manifest)) {

                                    [string[]]$ExtName = if ($Ext.name -notlike '__MSG*') {
                                        # Extension name is hardcoded in manifest
                                        $Ext.name
                                    } else {
                                        # Extension uses i18n localization (__MSG_appName__ format)
                                        # Must read from _locales/en*/messages.json to get actual name
                                        [string]$Locale = Join-Path $ExtSubfolder.Fullname '_locales'

                                        if (Test-Path $Locale -PathType Container) {
                                            # Look for English locale folders (en, en_US, en_GB, etc.)
                                            [string[]]$En = Get-ChildItem $Locale -Filter 'en*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName

                                            if ($En) {
                                                $En | ForEach-Object {
                                                    [string]$MsgPath = Join-Path $_ "messages.json"

                                                    if (Test-Path $MsgPath) {
                                                        [string]$MsgContent = (Get-Content $MsgPath -Raw -ErrorAction SilentlyContinue) -replace '\n',' '
                                                        $MsgContent -split '},' |
                                                            Select-String -AllMatches $NameRegex | ForEach-Object {
                                                                ([string]($_.Matches) -replace '"',$null).Trim()
                                                            }
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    [string]$ExtName = $ExtName | Select-Object -First 1

                                    # Apply name filter if specified
                                    if (-not $Match -or ($Match -and $ExtName -match $Match)) {

                                        [string]$ExtensionId = [string]($ExtFolder.Name)
                                        [string]$Version = if ($Ext.version) { $Ext.version } else { "Unknown" }

                                        # Check if extension is in malicious list
                                        [bool]$IsMalicious = $MaliciousList -contains $ExtensionId

                                        [hashtable]$ExtData = @{
                                            Hostname = $Hostname
                                            UserName = $UserName
                                            Browser = $BrowserName
                                            Profile = $ProfileName
                                            ExtensionId = $ExtensionId
                                            Name = $ExtName
                                            Version = $Version
                                        }

                                        Write-ExtensionEvent -Data $ExtData -LogName $LogName -SourceName $SourceName -IsMalicious $IsMalicious
                                        $Count++

                                        if ($IsMalicious) {
                                            $MaliciousCount++
                                        }
                                    }
                                }
                            } catch {
                                # Silent failure - continue scanning other extensions
                                continue
                            }
                        }
                    }
                }

            } elseif ($BrowserInfo.Type -eq 'Firefox') {
                # Firefox uses different structure: extensions.json in profile folders
                # Structure: %APPDATA%\Mozilla\Firefox\Profiles\{ProfileId}\extensions.json

                [string]$FirefoxRoot = Join-Path $User.LocalPath "AppData\Roaming\$($BrowserInfo.Path)"

                if (-not (Test-Path $FirefoxRoot -PathType Container)) {
                    continue
                }

                foreach ($ProfileDir in (Get-ChildItem $FirefoxRoot -Directory -ErrorAction SilentlyContinue)) {
                    [string]$ExtensionsJson = Join-Path $ProfileDir.FullName "extensions.json"

                    if (-not (Test-Path $ExtensionsJson -PathType Leaf)) {
                        continue
                    }

                    try {
                        [string]$ExtContent = Get-Content $ExtensionsJson -Raw -ErrorAction Stop
                        $ExtData = $ExtContent | ConvertFrom-Json

                        if ($ExtData.addons) {
                            foreach ($Addon in $ExtData.addons) {
                                # Firefox extensions can be identified by ID or sourceURI
                                # ID format varies: email-like (addon@developer.com) or GUID

                                if ($Addon.type -ne 'extension') {
                                    continue
                                }

                                [string]$ExtName = if ($Addon.defaultLocale.name) { $Addon.defaultLocale.name } else { $Addon.id }
                                [string]$ExtensionId = $Addon.id
                                [string]$Version = if ($Addon.version) { $Addon.version } else { "Unknown" }
                                [string]$ProfileName = $ProfileDir.Name

                                # Apply name filter if specified
                                if (-not $Match -or ($Match -and $ExtName -match $Match)) {

                                    # Check if extension is in malicious list (by ID)
                                    [bool]$IsMalicious = $MaliciousList -contains $ExtensionId

                                    [hashtable]$FFExtData = @{
                                        Hostname = $Hostname
                                        UserName = $UserName
                                        Browser = $BrowserName
                                        Profile = $ProfileName
                                        ExtensionId = $ExtensionId
                                        Name = $ExtName
                                        Version = $Version
                                    }

                                    Write-ExtensionEvent -Data $FFExtData -LogName $LogName -SourceName $SourceName -IsMalicious $IsMalicious
                                    $Count++

                                    if ($IsMalicious) {
                                        $MaliciousCount++
                                    }
                                }
                            }
                        }
                    } catch {
                        # Silent failure - continue scanning other profiles
                        continue
                    }
                }
            }
        }
    }

    # Only throw error if absolutely no extensions found (helps detect deployment issues)
    if ($Count -eq 0) {
        if ($Match) {
            throw "No result(s) for '$Match'."
        } else {
            throw "No result(s)."
        }
    } else {
        # Summary output for manual execution (silent in scheduled tasks)
        Write-Host "Scanned $Count extension(s). Found $MaliciousCount malicious extension(s)." -ForegroundColor $(if ($MaliciousCount -gt 0) { "Red" } else { "Green" })
    }
}

# Main execution block
try {
    # Legacy support for Windows 7/Server 2008 R2 with PowerShell 2.0
    # Load JSON serializer since ConvertFrom-Json not available until PS 3.0
    if ($PSVersionTable.PSVersion -lt [version]"3.0") {
        Add-Type -AssemblyName System.Web.Extensions
        $Script:Serializer = New-Object System.Web.Script.Serialization.JavascriptSerializer
    }

    # Create Event Log source if it doesn't exist (requires admin on first run)
    if (-not [System.Diagnostics.EventLog]::SourceExists($SourceName)) {
        New-EventLog -LogName $LogName -Source $SourceName -ErrorAction Stop
    }

    # Load malicious extensions list from file or URL
    [string[]]$MaliciousList = @()

    if ($MaliciousExtensionsPath) {
        # Use local file or UNC path
        if (Test-Path $MaliciousExtensionsPath) {
            Write-Host "Loading malicious extensions list from file: $MaliciousExtensionsPath" -ForegroundColor Cyan
            [string]$FileContent = Get-Content $MaliciousExtensionsPath -Raw
            $MaliciousList = $FileContent -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" -and $_ -notlike "#*" }
        } else {
            Write-Warning "Malicious extensions file not found: $MaliciousExtensionsPath. Proceeding without malicious list."
        }
    } else {
        # Download from URL
        Write-Host "Downloading malicious extensions list from $MaliciousExtensionsUrl..." -ForegroundColor Cyan
        $MaliciousList = Get-MaliciousExtensionList -Url $MaliciousExtensionsUrl
    }

    Write-Host "Loaded $($MaliciousList.Count) known malicious extension(s)." -ForegroundColor Cyan

    # Execute main scan
    Get-BrowserExtension -Match $Match -LogName $LogName -SourceName $SourceName -MaliciousList $MaliciousList

} catch {
    # Log fatal errors but exit gracefully for scheduled task execution
    Write-Error $_
    exit 1
}
