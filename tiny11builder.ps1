# Enable debugging
#Set-PSDebug -Trace 1

$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($myWindowsID)

# Check and run the script as admin if required.
if (!$myWindowsPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";
    $newProcess.Arguments = $myInvocation.MyCommand.Definition;
    $newProcess.Verb = "runas";
    [System.Diagnostics.Process]::Start($newProcess);
    exit
}

# Check if PowerShell Execution Policy is 'Restricted'.
if ((Get-ExecutionPolicy) -eq 'Restricted') {
    Write-Host "Your current PowerShell Execution Policy is set to 'Restricted', which prevents scripts from running. Do you want to change it to 'RemoteSigned'? (y/n)"
    if ((Read-Host) -eq 'y') {
        Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Confirm:$false
        Clear-Host
    } else {
        Write-Host "The script can't be run without changing the Execution Policy! Exiting..."
        Start-Sleep -Seconds 5
        exit
    }
}

# Start the transcript and prepare the window.
Start-Transcript -Path "$PSScriptRoot\tiny11.log"
Clear-Host
$Host.UI.RawUI.WindowTitle = "Tiny11 Builder"
Write-Host "Welcome to the Tiny11 Builder! Release: 30/12/2024"

New-Item -ItemType Directory -Force -Path "$PSScriptRoot\tiny11\sources" | Out-Null

do {
    $DriveLetter = Read-Host "Enter the mounted Windows 11 image drive letter"
    if ($DriveLetter -match '^[c-zC-Z]$') {
        $DriveLetter += ':'
    } else {
        Write-Output "The letter has to be between C and Z!"
    }
} while ($DriveLetter -notmatch '^[c-zC-Z]:$')

if ((Test-Path "$DriveLetter\sources\boot.wim") -eq $false -or (Test-Path "$DriveLetter\sources\install.wim") -eq $false) {
    if ((Test-Path "$DriveLetter\sources\install.esd") -eq $true) {
        Write-Host "Found install.esd, converting to .wim format."
        Get-WindowsImage -ImagePath $DriveLetter\sources\install.esd
        $index = Read-Host "Enter the image index"
        Write-Host "Proceeding with the conversion. This may take a while..."
        Export-WindowsImage -SourceImagePath $DriveLetter\sources\install.esd -SourceIndex $index -DestinationImagePath $PSScriptRoot\tiny11\sources\install.wim -Compressiontype Maximum -CheckIntegrity
    } else {
        Write-Host "Can't find Windows installation files in the specified drive letter! Make sure you entered it correct. Exiting..."
        Start-Sleep -Seconds 5
        exit
    }
}

Write-Host "Copying image."
Copy-Item -Path "$DriveLetter\*" -Destination "$PSScriptRoot\tiny11" -Recurse -Force | Out-Null

$esdFilePath = "$PSScriptRoot\tiny11\sources\install.esd"
if ((Test-Path $esdFilePath) -eq $true) {
    Set-ItemProperty -Path $esdFilePath -Name IsReadOnly -Value $false
    Remove-Item $esdFilePath | Out-Null
}

Get-WindowsImage -ImagePath $PSScriptRoot\tiny11\sources\install.wim
$index = Read-Host "Enter the image index"

Write-Host "Mounting Windows image. This may take a while..."

New-Item -ItemType Directory -Force -Path "$PSScriptRoot\scratchdir" | Out-Null

$adminSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
$adminGroup = $adminSID.Translate([System.Security.Principal.NTAccount])

$wimFilePath = "$PSScriptRoot\tiny11\sources\install.wim"
& 'takeown' '/f' $wimFilePath | Out-Null
& 'icacls' $wimFilePath '/grant' "$($adminGroup.Value):(F)" '/C' | Out-Null
Set-ItemProperty -Path $wimFilePath -Name IsReadOnly -Value $false
Mount-WindowsImage -ImagePath $wimFilePath -Index $index -Path "$PSScriptRoot\scratchdir"

$imageIntl = & 'dism' '/English' '/Get-Intl' "/Image:$($PSScriptRoot)\scratchdir"
$languageLine = $imageIntl -split '\n' | Where-Object { $_ -match 'Default system UI language : ([a-zA-Z]{2}-[a-zA-Z]{2})' }

if ($languageLine) {
    $languageCode = $Matches[1]
    Write-Host "Default system UI language code: $languageCode"
} else {
    Write-Host "[Warning] Default system UI language code not found!"
}

$imageInfo = & 'dism' '/English' '/Get-WimInfo' "/wimFile:$($PSScriptRoot)\tiny11\sources\install.wim" "/index:$index"
$lines = $imageInfo -split '\r?\n'

foreach ($line in $lines) {
    if ($line -like '*Architecture : *') {
        $arch = $line -replace 'Architecture : ',''
        # If the architecture is x64, replace it with amd64.
        if ($arch -eq 'x64') {
            $arch = 'amd64'
        }
        Write-Host "Architecture: $arch"
        break
    }
}

if (-not $arch) {
    Write-Host "[Warning] Architecture information not found!"
}

Write-Host "Mounting done! Performing removal of applications and packages."

$packages = & 'dism' '/English' "/image:$($PSScriptRoot)\scratchdir" '/Get-ProvisionedAppxPackages' | ForEach-Object {
     if ($_ -match 'PackageName : (.*)') { 
        $matches[1] 
    } 
}

$packagePrefixes = @(
'Clipchamp.Clipchamp_', 
'Microsoft.SecHealthUI_', 
'Microsoft.Windows.PeopleExperienceHost_', 
'Microsoft.Windows.PinningConfirmationDialog_', 
'Windows.CBSPreview_', 
'Microsoft.BingNews_', 
'Microsoft.BingWeather_', 
'Microsoft.GamingApp_', 
'Microsoft.GetHelp_', 
'Microsoft.Getstarted_', 
'Microsoft.MicrosoftOfficeHub_', 
'Microsoft.MicrosoftSolitaireCollection_', 
'Microsoft.People_', 
'Microsoft.PowerAutomateDesktop_', 
'Microsoft.Todos_', 
'Microsoft.WindowsAlarms_', 
'microsoft.windowscommunicationsapps_', 
'Microsoft.WindowsFeedbackHub_', 
'Microsoft.WindowsMaps_', 
'Microsoft.WindowsSoundRecorder_', 
'Microsoft.Xbox.TCUI_', 
'Microsoft.XboxGamingOverlay_', 
'Microsoft.XboxGameOverlay_', 
'Microsoft.XboxSpeechToTextOverlay_', 
'Microsoft.YourPhone_', 
'Microsoft.ZuneMusic_', 
'Microsoft.ZuneVideo_', 
'MicrosoftCorporationII.MicrosoftFamily_', 
'MicrosoftCorporationII.QuickAssist_', 
'MicrosoftTeams_', 
'Microsoft.549981C3F5F10_'
)

$packagesToRemove = $packages | Where-Object {
    $packageName = $_
    $packagePrefixes -contains ($packagePrefixes | Where-Object { $packageName -like "$_*" })
}

foreach ($package in $packagesToRemove) {
    Write-Host ' '
    Write-Host "Removing $package"
    & 'dism' '/English' "/image:$($PSScriptRoot)\scratchdir" '/Remove-ProvisionedAppxPackage' "/PackageName:$package"
}

$packagePatterns = @(
    'Microsoft-Windows-InternetExplorer-Optional-Package~', 

    'Microsoft-Windows-Kernel-LA57-FoD-Package~', 

    'Microsoft-Windows-LanguageFeatures-Handwriting-Package~', 
    'Microsoft-Windows-LanguageFeatures-OCR-Package~', 
    'Microsoft-Windows-LanguageFeatures-Speech-Package~', 
    'Microsoft-Windows-LanguageFeatures-TextToSpeech-Package~', 

    'Windows-Defender-Client-Package~', 

    'Microsoft-Windows-WordPad-FoD-Package~', 
    'Microsoft-Windows-TabletPCMath-Package~', 
    'Microsoft-Windows-StepsRecorder-Package~'
)

# Get all packages
$allPackages = & 'dism' "/image:$($PSScriptRoot)\scratchdir" '/Get-Packages' '/Format:Table'
$allPackages = $allPackages -split "`n" | Select-Object -Skip 1

foreach ($packagePattern in $packagePatterns) {
    # Filter the packages to remove
    $packagesToRemove = $allPackages | Where-Object { $_ -like "$packagePattern*" }

    foreach ($package in $packagesToRemove) {
        # Extract the package identity
        $packageIdentity = ($package -split "\s+")[0]

        Write-Host ' '
        Write-Host "Removing $packageIdentity"
        & 'dism' "/image:$($PSScriptRoot)\scratchdir" '/Remove-Package' "/PackageName:$packageIdentity"
    }
}

Write-Host "Removing Edge"
Remove-Item -Path "$PSScriptRoot\scratchdir\Program Files (x86)\Microsoft\Edge" -Recurse -Force | Out-Null
Remove-Item -Path "$PSScriptRoot\scratchdir\Program Files (x86)\Microsoft\EdgeCore" -Recurse -Force | Out-Null
Remove-Item -Path "$PSScriptRoot\scratchdir\Program Files (x86)\Microsoft\EdgeUpdate" -Recurse -Force | Out-Null

if ($arch -eq 'amd64' -or $arch -eq 'arm64') {
    $pkgName = $arch + "_microsoft-edge-webview_31bf3856ad364e35*"
    $folderPath = Get-ChildItem -Path "$PSScriptRoot\scratchdir\Windows\WinSxS" -Filter $pkgName -Directory | Select-Object -ExpandProperty FullName | Out-Null

    if ($folderPath) {
        & 'takeown' '/f' $folderPath '/r' | Out-Null
        & 'icacls' $folderPath '/grant' "$($adminGroup.Value):(F)" '/T' '/C' | Out-Null
        Remove-Item -Path $folderPath -Recurse -Force | Out-Null
    } else {
        Write-Host "[Warning] Microsoft Edge Webview package folder not found!"
    }
}

$fp = "$PSScriptRoot\scratchdir\Windows\System32\Microsoft-Edge-Webview"
& 'takeown' '/f' $fp '/r' | Out-Null
& 'icacls' $fp '/grant' "$($adminGroup.Value):(F)" '/T' '/C' | Out-Null
Remove-Item -Path $fp -Recurse -Force | Out-Null

Write-Host "Removing OneDrive"
$fp = "$PSScriptRoot\scratchdir\Windows\System32\OneDriveSetup.exe"
& 'takeown' '/f' $fp | Out-Null
& 'icacls' $fp '/grant' "$($adminGroup.Value):(F)" '/C' | Out-Null
Remove-Item -Path $fp -Force | Out-Null

Write-Host "Removals done! Performing registry tweaks."

Write-Host "Loading registry."
& 'reg' 'load' 'HKLM\zDEFAULT' "$PSScriptRoot\scratchdir\Windows\System32\config\default" | Out-Null
& 'reg' 'load' 'HKLM\zNTUSER' "$PSScriptRoot\scratchdir\Users\Default\ntuser.dat" | Out-Null
& 'reg' 'load' 'HKLM\zSOFTWARE' "$PSScriptRoot\scratchdir\Windows\System32\config\SOFTWARE" | Out-Null
& 'reg' 'load' 'HKLM\zSYSTEM' "$PSScriptRoot\scratchdir\Windows\System32\config\SYSTEM" | Out-Null

Write-Host "Bypassing system requirements (on the system image)"
& 'reg' 'add' 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' '/v' 'SV1' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' '/v' 'SV2' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' '/v' 'SV1' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' '/v' 'SV2' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassCPUCheck' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassRAMCheck' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassSecureBootCheck' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassStorageCheck' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassTPMCheck' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\MoSetup' '/v' 'AllowUpgradesWithUnsupportedTPMOrCPU' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null

Write-Host "Disabling Sponsored Apps"
& 'reg' 'add' 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'OemPreInstalledAppsEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'PreInstalledAppsEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SilentInstalledAppsEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' '/v' 'DisableWindowsConsumerFeatures' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'ContentDeliveryAllowed' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Start' '/v' 'ConfigureStartPins' '/t' 'REG_SZ' '/d' '{"pinnedList": [{}]}' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'ContentDeliveryAllowed' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'ContentDeliveryAllowed' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'FeatureManagementEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'OemPreInstalledAppsEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'PreInstalledAppsEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'PreInstalledAppsEverEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SilentInstalledAppsEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SoftLandingEnabled' '/t' 'REG_DWORD' '/d' '0' '/f'| Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SubscribedContentEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SubscribedContent-310093Enabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SubscribedContent-338388Enabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SubscribedContent-338389Enabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SubscribedContent-338393Enabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SubscribedContent-353694Enabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SubscribedContent-353696Enabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SubscribedContentEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SystemPaneSuggestionsEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\PushToInstall' '/v' 'DisablePushToInstall' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\MRT' '/v' 'DontOfferThroughWUAU' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'delete' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions' '/f' | Out-Null
& 'reg' 'delete' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' '/v' 'DisableConsumerAccountStateContent' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' '/v' 'DisableCloudOptimizedContent' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null

Write-Host "Enabling Local Accounts on OOBE"
& 'reg' 'add' 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\OOBE' '/v' 'BypassNRO' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
Copy-Item -Path "$PSScriptRoot\autounattend.xml" -Destination "$PSScriptRoot\scratchdir\Windows\System32\Sysprep\autounattend.xml" -Force | Out-Null

Write-Host "Disabling Reserved Storage"
& 'reg' 'add' 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager' '/v' 'ShippedWithReserves' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null

Write-Host "Disabling BitLocker Device Encryption"
& 'reg' 'add' 'HKLM\zSYSTEM\ControlSet001\Control\BitLocker' '/v' 'PreventDeviceEncryption' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null

Write-Host "Disabling Chat icon"
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Chat' '/v' 'ChatIcon' '/t' 'REG_DWORD' '/d' '3' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' '/v' 'TaskbarMn' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null

Write-Host "Removing Edge related registries"
& 'reg' 'delete' 'HKLM\zSOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge' '/f' | Out-Null
& 'reg' 'delete' 'HKLM\zSOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge Update' '/f' | Out-Null

Write-Host "Disabling OneDrive folder backup"
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\OneDrive' '/v' 'DisableFileSyncNGSC' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null

Write-Host "Disabling Telemetry"
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' '/v' 'Enabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Privacy' '/v' 'TailoredExperiencesWithDiagnosticDataEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy' '/v' 'HasAccepted' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Input\TIPC' '/v' 'Enabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization' '/v' 'RestrictImplicitInkCollection' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization' '/v' 'RestrictImplicitTextCollection' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization\TrainedDataStore' '/v' 'HarvestContacts' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Personalization\Settings' '/v' 'AcceptedPrivacyPolicy' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\DataCollection' '/v' 'AllowTelemetry' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\ControlSet001\Services\dmwappushservice' '/v' 'Start' '/t' 'REG_DWORD' '/d' '4' '/f' | Out-Null

Write-Host "Disabling sideloading of DevHome and Outlook"
& 'reg' 'add' 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\OutlookUpdate' '/v' 'workCompleted' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\DevHomeUpdate' '/v' 'workCompleted' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'delete' 'HKLM\zSOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate' '/f' | Out-Null
& 'reg' 'delete' 'HKLM\zSOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate' '/f' | Out-Null

Write-Host "Disabling bing in Start Menu"
& 'reg' 'add' 'HKLM\zNTUSER\Software\Policies\Microsoft\Windows\Explorer' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Policies\Microsoft\Windows\Explorer' '/v' 'ShowRunAsDifferentUserInStart' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Policies\Microsoft\Windows\Explorer' '/v' 'DisableSearchBoxSuggestions' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null

Write-Host "Disabling Windows Defender"
$services = @(
    'WinDefend', 
    'WdNisSvc', 
    'WdNisDrv', 
    'WdFilter', 
    'Sense'
)
foreach ($service in $services) {
    & 'reg' 'add' "HKLM\zSYSTEM\ControlSet001\Services\$service" '/v' 'Start' '/t' 'REG_DWORD' '/d' '4' '/f' | Out-Null
}
& 'reg' 'add' 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' '/v' 'SettingsPageVisibility' '/t' 'REG_SZ' '/d' 'hide:virus' '/f' | Out-Null

Write-Host "Tweaking done! Unloading registry."
& 'reg' 'unload' 'HKLM\zDEFAULT' | Out-Null
& 'reg' 'unload' 'HKLM\zNTUSER' | Out-Null
& 'reg' 'unload' 'HKLM\zSOFTWARE' | Out-Null
& 'reg' 'unload' 'HKLM\zSYSTEM' | Out-Null

Write-Host "Cleaning up and dismounting image."
Repair-WindowsImage -Path "$PSScriptRoot\scratchdir" -StartComponentCleanup -ResetBase
Dismount-WindowsImage -Path "$PSScriptRoot\scratchdir" -Save

Write-Host "Exporting image."
& 'dism' '/English' '/Export-Image' "/SourceImageFile:$PSScriptRoot\tiny11\sources\install.wim" "/SourceIndex:$index" "/DestinationImageFile:$PSScriptRoot\tiny11\sources\install2.wim" '/compress:recovery'

Remove-Item -Path "$PSScriptRoot\tiny11\sources\install.wim" -Force | Out-Null
Rename-Item -Path "$PSScriptRoot\tiny11\sources\install2.wim" -NewName 'install.wim' | Out-Null

Write-Host "Windows image completed! Mounting boot image."

$wimFilePath = "$PSScriptRoot\tiny11\sources\boot.wim"
& 'takeown' '/f' $wimFilePath | Out-Null
& 'icacls' $wimFilePath '/grant' "$($adminGroup.Value):(F)" '/C' | Out-Null
Set-ItemProperty -Path $wimFilePath -Name IsReadOnly -Value $false
Mount-WindowsImage -ImagePath $wimFilePath -Index 2 -Path "$PSScriptRoot\scratchdir"

Write-Host "Loading registry."
& 'reg' 'load' 'HKLM\zDEFAULT' "$PSScriptRoot\scratchdir\Windows\System32\config\default" | Out-Null
& 'reg' 'load' 'HKLM\zNTUSER' "$PSScriptRoot\scratchdir\Users\Default\ntuser.dat" | Out-Null
& 'reg' 'load' 'HKLM\zSYSTEM' "$PSScriptRoot\scratchdir\Windows\System32\config\SYSTEM" | Out-Null

Write-Host "Bypassing system requirements (on the setup image)"
& 'reg' 'add' 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' '/v' 'SV1' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' '/v' 'SV2' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' '/v' 'SV1' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' '/v' 'SV2' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassCPUCheck' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassRAMCheck' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassSecureBootCheck' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassStorageCheck' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassTPMCheck' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\MoSetup' '/v' 'AllowUpgradesWithUnsupportedTPMOrCPU' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null

Write-Host "Tweaking done! Unloading registry."
& 'reg' 'unload' 'HKLM\zDEFAULT' | Out-Null
& 'reg' 'unload' 'HKLM\zNTUSER' | Out-Null
& 'reg' 'unload' 'HKLM\zSYSTEM' | Out-Null

Write-Host "Dismounting image."
Dismount-WindowsImage -Path "$PSScriptRoot\scratchdir" -Save

Write-Host "The Tiny11 image is now completed! Proceeding with the making of the ISO image."

Write-Host "Copying unattended file for bypassing MS account on OOBE."
Copy-Item -Path "$PSScriptRoot\autounattend.xml" -Destination "$PSScriptRoot\tiny11\autounattend.xml" -Force | Out-Null

Write-Host "Creating ISO image."
$ADKDepTools = "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\$Env:PROCESSOR_ARCHITECTURE\Oscdimg"

if ([System.IO.Directory]::Exists($ADKDepTools)) {
    Write-Host "Will be using oscdimg.exe from the system ADK."
    $OSCDIMG = "$ADKDepTools\oscdimg.exe"
} else {
    Write-Host "ADK folder not found. Will be using bundled oscdimg.exe"
    $OSCDIMG = "$PSScriptRoot\oscdimg.exe"

    if ((Test-Path $OSCDIMG) -eq $false) {
        Write-Host "Downloading oscdimg.exe"
        Invoke-WebRequest -Uri 'https://msdl.microsoft.com/download/symbols/oscdimg.exe/3D44737265000/oscdimg.exe' -OutFile $OSCDIMG

        if ((Test-Path $OSCDIMG) -eq $false) {
            Write-Error "[Error] Download failed! Performing cleanup and exiting..."
            Remove-Item -Path "$PSScriptRoot\tiny11" -Recurse -Force | Out-Null
            Remove-Item -Path "$PSScriptRoot\scratchdir" -Recurse -Force | Out-Null
            Start-Sleep -Seconds 5
            exit
        }
    }
}

& "$OSCDIMG" '-m' '-o' '-u2' '-udfver102' "-bootdata:2#p0,e,b$PSScriptRoot\tiny11\boot\etfsboot.com#pEF,e,b$PSScriptRoot\tiny11\efi\microsoft\boot\efisys.bin" "$PSScriptRoot\tiny11" "$PSScriptRoot\tiny11.iso"

Write-Host "Performing cleanup."
Remove-Item -Path "$PSScriptRoot\tiny11" -Recurse -Force | Out-Null
Remove-Item -Path "$PSScriptRoot\scratchdir" -Recurse -Force | Out-Null

Read-Host "Creation done! Press enter to exit the script"
Stop-Transcript
exit
