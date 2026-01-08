# ============================================================================
# NOTICE: THIS SCRIPT IS NOT REQUIRED
# ============================================================================
# The main extension_audit.ps1 script automatically registers the Event Log
# source on first run. This standalone utility is provided for reference but
# is NOT needed for normal operation.
#
# Use this ONLY if you want to pre-register the Event Log source separately
# before deploying the main audit script (uncommon scenario).
# ============================================================================
#
# Register event source for Windows Event Log
#
# Usage:
#   .\register_sysmon_source.ps1 -LogName "Application" -SourceName "BrowserExtensions"
#   .\register_sysmon_source.ps1  (uses defaults)
#
# NOTE: Requires Administrator privileges to create Event Log sources

param(
    [string]$LogName = "Application",
    [string]$SourceName = "Browser Extension Alert"
)

try {
    if (-not [System.Diagnostics.EventLog]::SourceExists($SourceName)) {
        New-EventLog -LogName $LogName -Source $SourceName -ErrorAction Stop
        Write-Output "SUCCESS: Registered source '$SourceName' to '$LogName'"
    } else {
        Write-Output "ALREADY EXISTS: Source '$SourceName' is already registered"
    }
} catch {
    Write-Output "FAILED: $_"
    exit 1
}
