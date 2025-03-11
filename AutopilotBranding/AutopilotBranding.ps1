
function LogFile() {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$false)] [String] $message
	)

	$ts = get-date -f "yyyy/MM/dd hh:mm:ss tt"
	Write-Output "$ts $message"
}

# If we are running as a 32-bit process on an x64 system, re-launch as a 64-bit process
if ("$env:PROCESSOR_ARCHITEW6432" -ne "ARM64") {
    if (Test-Path "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe") {
        & "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy bypass -NoProfile -File "$PSCommandPath"
        Exit $lastexitcode
    }
}

# Create output folder
if (-not (Test-Path "$($env:ProgramData)\Microsoft\AutopilotBranding")) {
    Mkdir "$($env:ProgramData)\Microsoft\AutopilotBranding" -Force
}

# Start logging
Start-Transcript "$($env:ProgramData)\Microsoft\AutopilotBranding\AutopilotBranding.log"

# PREP: Load the Config.xml
$installFolder = "$PSScriptRoot\"
LogFile "Install folder: $installFolder"
LogFile "Loading configuration: $($installFolder)Config.xml"
[Xml]$config = Get-Content "$($installFolder)Config.xml"


# Set time zone
if ($config.Config.TimeZone) {
	LogFile "Setting time zone: $($config.Config.TimeZone)"
	try {
		Set-Timezone -Id $config.Config.TimeZone
        LogFile "SUCCESS: Time zone has been added. $_"
	} catch {
        LogFile "ERROR: Failed to set time zone. $_"
	}
} else {
	# Enable location services so the time zone will be set automatically (even when skipping the privacy page in OOBE) when an administrator signs in
	LogFile "No time zone configured. Enabling location services..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type "String" -Value "Allow" -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type "DWord" -Value 1 -Force
	Start-Service -Name "lfsvc" -ErrorAction SilentlyContinue
	LogFile "Location Services enabled."
}

# Add language packs
Get-ChildItem "$($installFolder)LPs" -Filter *.cab | % {
	LogFile "Adding language pack: $($_.FullName)"
	try {
		Add-WindowsPackage -Online -NoRestart -PackagePath $_.FullName -ErrorAction Stop
        LogFile "Success: Language pack has been added. $_"
	} catch {
		LogFile "ERROR: Failed to add language pack. $_"
	}
}

# Change language
if ($config.Config.Language) {
	LogFile "Configuring language using: $($config.Config.Language)"
	& $env:SystemRoot\System32\control.exe "intl.cpl,,/f:`"$($installFolder)$($config.Config.Language)`""
}

# Don't let Edge create a desktop shortcut (roams to OneDrive, creates mess)
try {
	LogFile "Turning off (old) Edge desktop shortcut"
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v DisableEdgeDesktopShortcutCreation /t REG_DWORD /d 1 /f /reg:64 | Out-Host
} catch {
	LogFile "ERROR: Failed to modify Edge shortcut registry. $_"
}

# Disable new Edge desktop icon
try {
LogFile "Turning off Edge desktop icon"
		reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" /v "CreateDesktopShortcutDefault" /t REG_DWORD /d 0 /f /reg:64 | Out-Host
} catch {
	LogFile "ERROR: Failed to modify Edge icon registry. $_"
}

# Creating tag file
Set-Content -Path "$($env:ProgramData)\Microsoft\AutopilotBranding\AutopilotBranding.ps1.tag" -Value "Installed"

Stop-Transcript
