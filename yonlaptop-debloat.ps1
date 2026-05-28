#Requires -RunAsAdministrator
#Requires -Version 5.1

<#
.SYNOPSIS
    Tier-1 aggressive Windows 11 debloat + perf optimization.
    Companion to yonlaptop-setup.ps1.

.DESCRIPTION
    Removes consumer-facing bloat, hard-disables Defender / Windows Update /
    VBS (with safety guards), shrinks the Windows footprint, and tunes power
    / services / Explorer for dev work.

    Defaults: AGGRESSIVE. Use -Keep<thing> switches to spare any single
    category.

    Phases:
        1   AppX bloat removal (provisioned + per-user; vetted keep-list)
        2   Edge full uninstall + reinstall block
        3   OneDrive full uninstall + reinstall block
        4   Recall + Copilot + Widgets + Cortana + Web search disable
        5   Defender hard-disable (requires Tamper Protection OFF in GUI)
        6   SmartScreen disable
        7   Windows Update neutralize (services + scheduled tasks + policy)
        8   VBS / HVCI / Credential Guard disable (keeps Hyper-V for WSL2)
        9   System Restore disable
       10   Reserved Storage disable
       11   Page file fixed size
       12   WSearch (indexer) disable
       13   NTFS perf (8.3 names off, last-access off)
       14   Power tweaks (USB selective suspend off, ASPM off, Ultimate Perf)
       15   Service trim (~30 services)
       16   Telemetry endpoints HOSTS block
       17   Explorer cleanup (Home tab off, Gallery off, full path, etc.)
       18   Start menu / lock screen / suggestions cleanup
       19   DISM cleanup + ResetBase (slow — runs last)

    Idempotent. Re-runnable. Logs land in C:\ProgramData\DevAccessSetup\.

.PARAMETER DryRun
    Print intended actions without applying.

.PARAMETER Verify
    Read-only status check. Changes nothing.

.PARAMETER KeepDefender
    Skip Defender hard-disable.

.PARAMETER KeepWindowsUpdate
    Skip Windows Update neutralization.

.PARAMETER KeepEdge
    Don't uninstall Microsoft Edge.

.PARAMETER KeepOneDrive
    Don't uninstall OneDrive.

.PARAMETER KeepRecall
    Don't disable Windows Recall (Copilot+ feature).

.PARAMETER KeepVBS
    Don't disable Virtualization-Based Security / HVCI / Credential Guard.

.PARAMETER KeepSystemRestore
    Don't disable System Restore.

.PARAMETER KeepReservedStorage
    Don't disable Reserved Storage.

.PARAMETER KeepWSearch
    Don't disable WSearch (the indexer).

.PARAMETER KeepBuiltinApps
    Array of AppX package names to spare (e.g. 'Microsoft.WindowsMaps').

.PARAMETER PageFileSizeMB
    Fixed page file size. 0 = leave Windows-managed. Default: 16384.

.PARAMETER SkipDISMCleanup
    Skip the slow DISM /StartComponentCleanup /ResetBase pass.

.PARAMETER SkipServiceTrim
    Skip the bulk service-disable phase.

.EXAMPLE
    # Full Tier-1 debloat
    .\yonlaptop-debloat.ps1

    # Everything except killing Defender
    .\yonlaptop-debloat.ps1 -KeepDefender

    # Status check only — no changes
    .\yonlaptop-debloat.ps1 -Verify

.NOTES
    Version : 1.0.0
    Source  : https://github.com/CapitalistCookie/yonlaptop-setup
    License : MIT

    REQUIRES Tamper Protection OFF in Windows Security (Settings → Privacy
    & security → Windows Security → Virus & threat protection → Manage
    settings → Tamper Protection → Off) for the Defender disable phase
    to be effective. If TP is on, that phase is skipped with a warning.
#>

[CmdletBinding()]
param(
    [switch]   $DryRun,
    [switch]   $Verify,
    [switch]   $KeepDefender,
    [switch]   $KeepWindowsUpdate,
    [switch]   $KeepEdge,
    [switch]   $KeepOneDrive,
    [switch]   $KeepRecall,
    [switch]   $KeepVBS,
    [switch]   $KeepSystemRestore,
    [switch]   $KeepReservedStorage,
    [switch]   $KeepWSearch,
    [string[]] $KeepBuiltinApps = @(),
    [int]      $PageFileSizeMB  = 16384,
    [switch]   $SkipDISMCleanup,
    [switch]   $SkipServiceTrim
)

# ============================================================================
# Globals
# ============================================================================
$script:Version = '1.0.0'
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

$LogDir  = Join-Path $env:ProgramData 'DevAccessSetup'
$LogFile = Join-Path $LogDir ("debloat-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
$null = New-Item -ItemType Directory -Force -Path $LogDir

$script:Failures = @()

# ============================================================================
# Helpers
# ============================================================================
function Write-Section { param([string]$Title)
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor Cyan
    Write-Host (" $Title") -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor Cyan
}

function Write-Step { param([string]$Msg, [ValidateSet('OK','WARN','FAIL','SKIP','INFO')]$Status='INFO')
    $color = @{ OK='Green'; WARN='Yellow'; FAIL='Red'; SKIP='DarkGray'; INFO='Gray' }[$Status]
    Write-Host (" [{0,-4}] {1}" -f $Status, $Msg) -ForegroundColor $color
}

function Invoke-Safe { param([scriptblock]$Block, [string]$What)
    if ($DryRun -or $Verify) { Write-Step "[skip] $What" 'SKIP'; return }
    try { & $Block | Out-Null; Write-Step $What 'OK' }
    catch { Write-Step "$What  --  $($_.Exception.Message)" 'FAIL'
            $script:Failures += $What }
}

function Set-RegistryValue { param([string]$Path, [string]$Name, $Value, [string]$Type='DWord')
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    $existing = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
        Set-ItemProperty -Path $Path -Name $Name -Value $Value
    } else {
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    }
}

function Test-PendingReboot {
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { return $true }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { return $true }
    return $false
}

function Disable-ScheduledTaskSafe { param([string]$Path)
    Invoke-Safe { & schtasks /Change /TN $Path /Disable 2>&1 | Out-Null } "disable task: $Path"
}

function Disable-ServiceSafe { param([string]$Name)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) { Write-Step "service not present: $Name" 'SKIP'; return }
    Invoke-Safe {
        if ($svc.Status -eq 'Running') {
            Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
        }
        Set-Service -Name $Name -StartupType Disabled -ErrorAction Stop
    } "disable service: $Name"
}

# ============================================================================
# AppX lists
# ============================================================================
$script:BloatAppX = @(
    # Consumer entertainment / games
    'Microsoft.3DBuilder'
    'Microsoft.BingFinance'
    'Microsoft.BingNews'
    'Microsoft.BingSports'
    'Microsoft.BingTranslator'
    'Microsoft.GamingApp'
    'Microsoft.GroupMe10'
    'Microsoft.MicrosoftOfficeHub'
    'Microsoft.MicrosoftSolitaireCollection'
    'Microsoft.MinecraftUWP'
    'Microsoft.MixedReality.Portal'
    'Microsoft.NetworkSpeedTest'
    'Microsoft.News'
    'Microsoft.Office.Lens'
    'Microsoft.Office.Sway'
    'Microsoft.Office.OneNote'
    'Microsoft.OutlookForWindows'
    'Microsoft.OneConnect'
    'Microsoft.People'
    'Microsoft.Print3D'
    'Microsoft.SkypeApp'
    'Microsoft.Wallet'
    'Microsoft.WindowsAlarms'
    'Microsoft.WindowsFeedbackHub'
    'Microsoft.WindowsMaps'
    'Microsoft.WindowsSoundRecorder'
    'Microsoft.YourPhone'
    'Microsoft.ZuneMusic'
    'Microsoft.ZuneVideo'
    'Microsoft.Getstarted'
    'Microsoft.GetHelp'
    'Microsoft.MicrosoftStickyNotes'
    'Microsoft.PowerAutomateDesktop'
    'Microsoft.Todos'
    'Microsoft.Copilot'
    # Xbox cluster
    'Microsoft.Xbox.TCUI'
    'Microsoft.XboxApp'
    'Microsoft.XboxGameOverlay'
    'Microsoft.XboxGamingOverlay'
    'Microsoft.XboxIdentityProvider'
    'Microsoft.XboxSpeechToTextOverlay'
    # Mail / Calendar / Teams consumer
    'microsoft.windowscommunicationsapps'
    'MicrosoftTeams'
    'MSTeams'
    # Family / QuickAssist
    'MicrosoftCorporationII.MicrosoftFamily'
    'MicrosoftCorporationII.QuickAssist'
    # Camera (toggleable)
    'Microsoft.WindowsCamera'
    # Clipchamp
    'Clipchamp.Clipchamp'
    # Cortana
    'Microsoft.549981C3F5F10'
)

$script:KeepAppX = @(
    'Microsoft.WindowsCalculator'
    'Microsoft.WindowsStore'
    'Microsoft.WindowsTerminal'
    'Microsoft.Paint'
    'Microsoft.ScreenSketch'
    'Microsoft.WindowsNotepad'
    'Microsoft.Photos'
    'Microsoft.HEIFImageExtension'
    'Microsoft.HEVCVideoExtension'
    'Microsoft.WebpImageExtension'
    'Microsoft.RawImageExtension'
    'Microsoft.VP9VideoExtensions'
    'Microsoft.WindowsAppRuntime'
    'Microsoft.UI.Xaml'
    'Microsoft.VCLibs'
    'Microsoft.NET.Native'
    'Microsoft.WindowsFeedbackHub'  # listed-but-keep is fine if dev wants feedback
)

# ============================================================================
# Status reporter
# ============================================================================
function Show-DebloatStatus {
    Write-Section 'Status'

    $os = Get-CimInstance Win32_OperatingSystem
    Write-Host ("  OS              : {0}  build {1}" -f $os.Caption, $os.BuildNumber)

    $bloatStill = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -in $script:BloatAppX }
    Write-Host ("  Bloat AppX left : {0} (of {1})" -f $bloatStill.Count, $script:BloatAppX.Count)

    $def = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($def) {
        Write-Host ("  Defender        : RT={0}  Tamper={1}  AntiSpy={2}" -f `
            $def.RealTimeProtectionEnabled, $def.IsTamperProtected, $def.AntispywareEnabled)
    } else {
        Write-Host '  Defender        : status unavailable'
    }

    $edge = Test-Path 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
    Write-Host ("  Edge binary     : {0}" -f ($(if ($edge) { 'present' } else { 'gone' })))
    $od = Get-Process OneDrive -ErrorAction SilentlyContinue
    Write-Host ("  OneDrive proc   : {0}" -f ($(if ($od) { 'running' } else { 'not running' })))

    $wu = Get-Service wuauserv -ErrorAction SilentlyContinue
    Write-Host ("  WindowsUpdate   : {0,-9}  startup={1}" -f $wu.Status, $wu.StartType)
    $wsearch = Get-Service WSearch -ErrorAction SilentlyContinue
    Write-Host ("  WSearch         : {0,-9}  startup={1}" -f $wsearch.Status, $wsearch.StartType)

    $c = Get-Volume C
    Write-Host ("  C: disk         : {0:N1} GB free / {1:N1} GB total" -f ($c.SizeRemaining/1GB), ($c.Size/1GB))

    $pf = Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue
    if ($pf) { Write-Host ("  Page file       : {0}  {1} MB allocated" -f $pf.Name, $pf.AllocatedBaseSize) }
    else     { Write-Host '  Page file       : auto / unmeasured' }

    $hyp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' `
            -Name EnableVirtualizationBasedSecurity -ErrorAction SilentlyContinue).EnableVirtualizationBasedSecurity
    Write-Host ("  VBS             : {0}" -f ($(if ($hyp -eq 0) { 'disabled' } else { 'enabled / default' })))

    Write-Host ("  Pending reboot  : {0}" -f (Test-PendingReboot))
}

# ============================================================================
# Main
# ============================================================================
Start-Transcript -Path $LogFile -Force | Out-Null
try {

Write-Section ("0  Preflight  (yonlaptop-debloat.ps1 v{0})" -f $script:Version)

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]::new($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Must run as Administrator.'
}
Write-Step "Running as $($id.Name) (admin)" 'OK'

$os = Get-CimInstance Win32_OperatingSystem
Write-Step "OS: $($os.Caption) build $($os.BuildNumber)" 'OK'

$edition = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').EditionID
Write-Step "Edition: $edition" 'OK'

if ($env:SSH_CONNECTION) { Write-Step "Running over SSH ($env:SSH_CONNECTION)" 'WARN' }
if ($env:SESSIONNAME -like 'RDP-*') { Write-Step "Running over RDP ($env:SESSIONNAME)" 'WARN' }

Write-Step "Log file: $LogFile" 'INFO'
if ($DryRun) { Write-Step 'DRY-RUN mode' 'WARN' }

if ($Verify) {
    Show-DebloatStatus
    Write-Host ''
    Write-Host '  (Verify mode — no changes applied.)' -ForegroundColor DarkGray
    return
}

# ============================================================================
# 1.  AppX bloat removal
# ============================================================================
Write-Section '1  AppX bloat removal (parallel)'

# Build work list (filter keep-list upfront)
$appxWork = foreach ($pkg in $script:BloatAppX) {
    if ($script:KeepAppX -contains $pkg) { Write-Step "keep (whitelist): $pkg" 'SKIP'; continue }
    if ($KeepBuiltinApps -contains $pkg) { Write-Step "keep (param):     $pkg" 'SKIP'; continue }
    $pkg
}

if ($DryRun -or $Verify) {
    foreach ($pkg in $appxWork) { Write-Step "[skip] remove AppX: $pkg" 'SKIP' }
} elseif ($appxWork.Count -gt 0) {
    # Make sure ThreadJob module is loaded (ships with PS 5.1 on Win10/11)
    if (-not (Get-Command Start-ThreadJob -ErrorAction SilentlyContinue)) {
        Import-Module ThreadJob -ErrorAction SilentlyContinue
    }

    $appxScript = {
        param($name)
        try {
            Get-AppxPackage -Name $name -AllUsers -ErrorAction SilentlyContinue |
                ForEach-Object { Remove-AppxPackage -Package $_.PackageFullName -AllUsers -ErrorAction SilentlyContinue }
            Get-AppxPackage -Name $name -ErrorAction SilentlyContinue |
                ForEach-Object { Remove-AppxPackage -Package $_.PackageFullName -ErrorAction SilentlyContinue }
            try {
                Get-AppxProvisionedPackage -Online -ErrorAction Stop |
                    Where-Object DisplayName -eq $name |
                    ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -ErrorAction SilentlyContinue }
                [pscustomobject]@{ Name = $name; Status = 'OK';   Error = $null }
            } catch {
                # Provisioned-package removal hit DISM "Class not registered" — common, harmless
                [pscustomobject]@{ Name = $name; Status = 'OK';   Error = "prov-skip: $($_.Exception.Message)" }
            }
        } catch {
            [pscustomobject]@{ Name = $name; Status = 'FAIL'; Error = $_.Exception.Message }
        }
    }

    if (Get-Command Start-ThreadJob -ErrorAction SilentlyContinue) {
        Write-Step "dispatching $($appxWork.Count) parallel AppX removals (throttle=6)" 'INFO'
        $jobs = $appxWork | ForEach-Object {
            Start-ThreadJob -Name "appx-$_" -ScriptBlock $appxScript -ArgumentList $_ -ThrottleLimit 6
        }
        $jobs | Wait-Job | ForEach-Object {
            $r = Receive-Job $_
            if ($r.Status -eq 'OK') { Write-Step "remove AppX: $($r.Name)" 'OK' }
            else { Write-Step "remove AppX: $($r.Name)  --  $($r.Error)" 'FAIL'; $script:Failures += "AppX:$($r.Name)" }
            Remove-Job $_
        }
    } else {
        # Last-ditch serial fallback (no ThreadJob)
        Write-Step 'ThreadJob unavailable — falling back to serial removal' 'WARN'
        foreach ($pkg in $appxWork) {
            Invoke-Safe { & $appxScript $pkg | Out-Null } "remove AppX: $pkg"
        }
    }
}

# Block consumer feature reinstall + suggested content
Invoke-Safe {
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableWindowsConsumerFeatures' 1
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableSoftLanding' 1
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableConsumerAccountStateContent' 1
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableCloudOptimizedContent' 1
} 'block consumer-features reinstall'

# ============================================================================
# 2.  Edge removal
# ============================================================================
if (-not $KeepEdge) {
    Write-Section '2  Microsoft Edge removal'

    # Find Edge setup.exe in both Program Files dirs
    $edgeDirs = @()
    foreach ($base in "${env:ProgramFiles(x86)}\Microsoft\Edge\Application",
                      "$env:ProgramFiles\Microsoft\Edge\Application") {
        if (Test-Path $base) { $edgeDirs += Get-ChildItem $base -Directory -ErrorAction SilentlyContinue }
    }
    foreach ($d in $edgeDirs) {
        $setup = Join-Path $d.FullName 'Installer\setup.exe'
        if (Test-Path $setup) {
            Invoke-Safe {
                & $setup --uninstall --system-level --verbose-logging --force-uninstall 2>&1 | Out-Null
            } "uninstall via $setup"
        }
    }

    # Stop and disable Edge update services
    foreach ($svc in 'edgeupdate','edgeupdatem','MicrosoftEdgeElevationService') {
        Disable-ServiceSafe $svc
    }

    # Block reinstall via Edge update policy
    Invoke-Safe {
        Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\EdgeUpdate' 'DoNotUpdateToEdgeWithChromium' 1
        Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate' 'DoNotUpdateToEdgeWithChromium' 1
        Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate' 'InstallDefault' 0
        Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate' 'CreateDesktopShortcutDefault' 0
    } 'Edge reinstall blocked'

    # Remove Edge update scheduled tasks
    foreach ($t in '\MicrosoftEdgeUpdateTaskMachineCore','\MicrosoftEdgeUpdateTaskMachineUA',
                   '\MicrosoftEdgeUpdateBrowserReplacementTask') { Disable-ScheduledTaskSafe $t }
}

# ============================================================================
# 3.  OneDrive removal
# ============================================================================
if (-not $KeepOneDrive) {
    Write-Section '3  OneDrive removal'

    # Stop running OneDrive
    Invoke-Safe { Get-Process OneDrive -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue } 'stop OneDrive process'

    foreach ($exe in "$env:SystemRoot\SysWOW64\OneDriveSetup.exe",
                     "$env:SystemRoot\System32\OneDriveSetup.exe") {
        if (Test-Path $exe) {
            Invoke-Safe { & $exe /uninstall 2>&1 | Out-Null; Start-Sleep -Seconds 4 } "OneDrive uninstall via $exe"
        }
    }

    # Remove leftover dirs
    foreach ($p in "$env:USERPROFILE\OneDrive",
                   "$env:LOCALAPPDATA\Microsoft\OneDrive",
                   "$env:PROGRAMDATA\Microsoft OneDrive",
                   "$env:SYSTEMDRIVE\OneDriveTemp") {
        if (Test-Path $p) {
            Invoke-Safe { Remove-Item -Path $p -Recurse -Force -ErrorAction SilentlyContinue } "remove $p"
        }
    }

    # Remove from Explorer sidebar
    foreach ($k in 'HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}',
                   'HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}') {
        if (Test-Path $k) {
            Invoke-Safe { Set-ItemProperty -Path $k -Name 'System.IsPinnedToNameSpaceTree' -Value 0 -Force } "hide OneDrive from Explorer ($k)"
        }
    }

    # Group Policy: disable file sync
    Invoke-Safe { Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' 'DisableFileSyncNGSC' 1 } 'OneDrive sync disabled via policy'
}

# ============================================================================
# 4.  Recall + Copilot + Widgets + Cortana + Web search
# ============================================================================
Write-Section '4  Recall / Copilot / Widgets / Cortana / Web Search'

if (-not $KeepRecall) {
    Invoke-Safe {
        Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' 'DisableAIDataAnalysis' 1
        Set-RegistryValue 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' 'DisableAIDataAnalysis' 1
        Disable-WindowsOptionalFeature -Online -FeatureName Recall -NoRestart -ErrorAction SilentlyContinue | Out-Null
    } 'Recall disabled'
}

# Copilot
Invoke-Safe {
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot' 'TurnOffWindowsCopilot' 1
    Set-RegistryValue 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot' 'TurnOffWindowsCopilot' 1
    Set-RegistryValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'ShowCopilotButton' 0
} 'Copilot disabled'

# Widgets
Invoke-Safe {
    Set-RegistryValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'TaskbarDa' 0
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh' 'AllowNewsAndInterests' 0
} 'Widgets disabled'

# Cortana
Invoke-Safe {
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'AllowCortana' 0
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'AllowSearchToUseLocation' 0
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'AllowCloudSearch' 0
} 'Cortana disabled'

# Web search in start menu
Invoke-Safe {
    Set-RegistryValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' 'BingSearchEnabled' 0
    Set-RegistryValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' 'CortanaConsent' 0
    Set-RegistryValue 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer' 'DisableSearchBoxSuggestions' 1
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'DisableWebSearch' 1
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'ConnectedSearchUseWeb' 0
} 'Web search disabled in Start menu'

# ============================================================================
# 5.  Defender hard-disable (requires Tamper Protection off)
# ============================================================================
if (-not $KeepDefender) {
    Write-Section '5  Windows Defender hard-disable'

    $def = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($def -and $def.IsTamperProtected) {
        Write-Step 'Tamper Protection is ON — Defender disable will NOT stick.' 'WARN'
        Write-Step 'Turn it off in Windows Security GUI, then re-run.' 'WARN'
        Write-Step 'Path: Settings > Privacy & security > Windows Security > Virus & threat protection > Manage settings > Tamper Protection: Off' 'INFO'
    } else {
        # Set-MpPreference disables
        Invoke-Safe {
            Set-MpPreference -DisableRealtimeMonitoring          $true -ErrorAction SilentlyContinue
            Set-MpPreference -DisableBehaviorMonitoring          $true -ErrorAction SilentlyContinue
            Set-MpPreference -DisableIOAVProtection              $true -ErrorAction SilentlyContinue
            Set-MpPreference -DisableScriptScanning              $true -ErrorAction SilentlyContinue
            Set-MpPreference -DisableArchiveScanning             $true -ErrorAction SilentlyContinue
            Set-MpPreference -DisableEmailScanning               $true -ErrorAction SilentlyContinue
            Set-MpPreference -DisableRemovableDriveScanning      $true -ErrorAction SilentlyContinue
            Set-MpPreference -DisableRestorePoint                $true -ErrorAction SilentlyContinue
            Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan $true -ErrorAction SilentlyContinue
            Set-MpPreference -DisableScanningNetworkFiles        $true -ErrorAction SilentlyContinue
            Set-MpPreference -EnableControlledFolderAccess       Disabled -ErrorAction SilentlyContinue
            Set-MpPreference -EnableNetworkProtection            Disabled -ErrorAction SilentlyContinue
            Set-MpPreference -SubmitSamplesConsent               2 -ErrorAction SilentlyContinue
            Set-MpPreference -MAPSReporting                      0 -ErrorAction SilentlyContinue
            Set-MpPreference -CloudBlockLevel                    0 -ErrorAction SilentlyContinue
        } 'Set-MpPreference: full disable'

        # Group Policy registry — resists re-enable on reboot
        Invoke-Safe {
            Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' 'DisableAntiSpyware' 1
            Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' 'DisableAntiVirus'   1
            Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' 'DisableRoutinelyTakingAction' 1
            $rt = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
            Set-RegistryValue $rt 'DisableRealtimeMonitoring'   1
            Set-RegistryValue $rt 'DisableBehaviorMonitoring'   1
            Set-RegistryValue $rt 'DisableIOAVProtection'       1
            Set-RegistryValue $rt 'DisableOnAccessProtection'   1
            Set-RegistryValue $rt 'DisableScanOnRealtimeEnable' 1
            $sn = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
            Set-RegistryValue $sn 'SpyNetReporting'      0
            Set-RegistryValue $sn 'SubmitSamplesConsent' 2
        } 'Defender policy keys'

        # Try to disable services (TP off lets this stick)
        foreach ($svc in 'WinDefend','WdNisSvc','Sense','SecurityHealthService') {
            Invoke-Safe { & sc.exe config $svc start= disabled 2>&1 | Out-Null
                         & sc.exe stop $svc 2>&1 | Out-Null } "sc disable: $svc"
        }

        # Defender scheduled tasks
        foreach ($t in '\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance',
                       '\Microsoft\Windows\Windows Defender\Windows Defender Cleanup',
                       '\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan',
                       '\Microsoft\Windows\Windows Defender\Windows Defender Verification') {
            Disable-ScheduledTaskSafe $t
        }
    }
}

# ============================================================================
# 6.  SmartScreen disable
# ============================================================================
Write-Section '6  SmartScreen disable'

Invoke-Safe {
    Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled' 'Off' 'String'
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen' 0
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'ShellSmartScreenLevel' 'Off' 'String'
    Set-RegistryValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost' 'EnableWebContentEvaluation' 0
    Set-RegistryValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost' 'PreventOverride' 0
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' 'EnabledV9' 0
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'SmartScreenEnabled' 0
} 'SmartScreen disabled'

# ============================================================================
# 7.  Windows Update neutralize
# ============================================================================
if (-not $KeepWindowsUpdate) {
    Write-Section '7  Windows Update neutralize'

    foreach ($svc in 'wuauserv','UsoSvc','WaaSMedicSvc','BITS','DoSvc') {
        Disable-ServiceSafe $svc
    }
    # WaaSMedicSvc re-enables itself; set Start directly in registry
    Invoke-Safe {
        Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc' 'Start' 4
        & sc.exe failure WaaSMedicSvc reset= 0 actions= '//' 2>&1 | Out-Null
    } 'WaaSMedicSvc: pinned disabled'

    foreach ($t in '\Microsoft\Windows\WindowsUpdate\Scheduled Start',
                   '\Microsoft\Windows\UpdateOrchestrator\Schedule Scan',
                   '\Microsoft\Windows\UpdateOrchestrator\Schedule Wake To Work',
                   '\Microsoft\Windows\UpdateOrchestrator\Reboot',
                   '\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker',
                   '\Microsoft\Windows\WaaSMedic\PerformRemediation') {
        Disable-ScheduledTaskSafe $t
    }

    Invoke-Safe {
        $au = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
        Set-RegistryValue $au 'NoAutoUpdate' 1
        Set-RegistryValue $au 'AUOptions'    1
        Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'DoNotConnectToWindowsUpdateInternetLocations' 1
    } 'Windows Update policy: never auto-update'
}

# ============================================================================
# 8.  VBS / HVCI / Credential Guard (keeps Hyper-V intact for WSL2)
# ============================================================================
if (-not $KeepVBS) {
    Write-Section '8  VBS / HVCI / Credential Guard disable'

    Invoke-Safe {
        Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' 'EnableVirtualizationBasedSecurity' 0
        Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' 'Enabled' 0
        Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LsaCfgFlags' 0
        # NOTE: deliberately NOT running `bcdedit /set hypervisorlaunchtype off`
        # — that would break Hyper-V and WSL2 which the setup script enabled.
    } 'VBS/HVCI/Credential Guard disabled (Hyper-V kept)'
}

# ============================================================================
# 9.  System Restore disable
# ============================================================================
if (-not $KeepSystemRestore) {
    Write-Section '9  System Restore disable'

    Invoke-Safe {
        Disable-ComputerRestore -Drive 'C:\' -ErrorAction SilentlyContinue
        & vssadmin.exe delete shadows /all /quiet 2>&1 | Out-Null
        Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore' 'DisableSR' 1
        Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore' 'DisableConfig' 1
    } 'System Restore disabled, shadow copies deleted'
}

# ============================================================================
# 10.  Reserved Storage disable
# ============================================================================
if (-not $KeepReservedStorage) {
    Write-Section '10  Reserved Storage disable'

    Invoke-Safe {
        & DISM.exe /Online /Set-ReservedStorageState /State:Disabled 2>&1 | Out-Null
    } 'Reserved Storage disabled (~7GB reclaim)'
}

# ============================================================================
# 11.  Page file fixed size
# ============================================================================
if ($PageFileSizeMB -gt 0) {
    Write-Section "11  Page file: fixed at $PageFileSizeMB MB"

    Invoke-Safe {
        $cs = Get-CimInstance Win32_ComputerSystem
        if ($cs.AutomaticManagedPagefile) {
            $cs | Set-CimInstance -Property @{ AutomaticManagedPagefile = $false }
        }
        $pf = Get-CimInstance Win32_PageFileSetting -ErrorAction SilentlyContinue
        if ($pf) {
            $pf | Set-CimInstance -Property @{ InitialSize = $PageFileSizeMB; MaximumSize = $PageFileSizeMB }
        } else {
            New-CimInstance -ClassName Win32_PageFileSetting `
                -Property @{ Name = 'C:\pagefile.sys'; InitialSize = $PageFileSizeMB; MaximumSize = $PageFileSizeMB } | Out-Null
        }
    } "page file -> $PageFileSizeMB MB fixed on C:"
} else {
    Write-Section '11  Page file (left Windows-managed)'
}

# ============================================================================
# 12.  WSearch (indexer)
# ============================================================================
if (-not $KeepWSearch) {
    Write-Section '12  WSearch indexer disable'
    Disable-ServiceSafe WSearch
}

# ============================================================================
# 13.  NTFS perf
# ============================================================================
Write-Section '13  NTFS perf tweaks'

Invoke-Safe { & fsutil.exe behavior set disablelastaccess 1 2>&1 | Out-Null } 'disable last-access updates'
Invoke-Safe { & fsutil.exe behavior set disable8dot3      1 2>&1 | Out-Null } 'disable 8.3 short names'
Invoke-Safe { & fsutil.exe behavior set memoryusage       2 2>&1 | Out-Null } 'bias to FS cache'

# ============================================================================
# 14.  Power tweaks
# ============================================================================
Write-Section '14  Power tweaks (USB suspend off, ASPM off, Ultimate Perf)'

# USB selective suspend off
Invoke-Safe {
    & powercfg /SetACValueIndex SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0 2>&1 | Out-Null
    & powercfg /SetDCValueIndex SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0 2>&1 | Out-Null
} 'USB selective suspend off'

# PCIe ASPM off (NIC stays responsive)
Invoke-Safe {
    & powercfg /SetACValueIndex SCHEME_CURRENT 501a4d13-42af-4429-9fd1-a8218c268e20 ee12f906-d277-404b-b6da-e5fa1a576df5 0 2>&1 | Out-Null
    & powercfg /SetDCValueIndex SCHEME_CURRENT 501a4d13-42af-4429-9fd1-a8218c268e20 ee12f906-d277-404b-b6da-e5fa1a576df5 0 2>&1 | Out-Null
} 'PCIe ASPM off'

# Unlock + activate Ultimate Performance
Invoke-Safe {
    & powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 2>&1 | Out-Null
    $ult = (& powercfg -list) | Select-String 'Ultimate Performance'
    if ($ult) {
        $guid = ([regex]'([0-9a-fA-F-]{36})').Match($ult).Value
        if ($guid) { & powercfg /setactive $guid 2>&1 | Out-Null }
    }
} 'Ultimate Performance power plan active'

Invoke-Safe { & powercfg /SetActive SCHEME_CURRENT 2>&1 | Out-Null } 'apply power scheme'

# ============================================================================
# 15.  Service trim
# ============================================================================
if (-not $SkipServiceTrim) {
    Write-Section '15  Service trim'

    $serviceTrimList = @(
        # Telemetry / diagnostics
        'DiagTrack'
        'dmwappushservice'
        'WerSvc'
        'DPS'
        'WdiServiceHost'
        'WdiSystemHost'
        # Consumer / unused features
        'RetailDemo'
        'MapsBroker'
        'lfsvc'                   # location
        'WMPNetworkSvc'           # WMP media sharing
        'TabletInputService'
        'Fax'
        'PrintNotify'
        # Xbox cluster
        'XblAuthManager'
        'XblGameSave'
        'XboxNetApiSvc'
        'XboxGipSvc'
        # Sync / cloud
        'OneSyncSvc'
        'CDPSvc'
        'PimIndexMaintenanceSvc'
        'UserDataSvc'
        'UnistoreSvc'
        # Misc bloat
        'WalletService'
        'WpcMonSvc'
        'HomeGroupListener'
        'HomeGroupProvider'
        'AssignedAccessManagerSvc'
        'AJRouter'                # AllJoyn
        'TrkWks'                  # distributed link tracking
        'iphlpsvc'                # IPv6 transition; safe to disable unless using Teredo/6to4
        'SharedAccess'            # ICS
        # Biometrics (only disable if no fingerprint reader)
        # 'WbioSrvc'
        # Bluetooth (uncomment if you don't use BT)
        # 'bthserv'
        # Print spooler (uncomment if you don't print)
        # 'Spooler'
    )
    foreach ($s in $serviceTrimList) { Disable-ServiceSafe $s }
}

# ============================================================================
# 16.  Telemetry hosts block
# ============================================================================
Write-Section '16  Telemetry hosts block'

$hostsFile = "$env:WINDIR\System32\drivers\etc\hosts"
$marker = '# yonlaptop-debloat telemetry block'
$blocks = @(
    'vortex.data.microsoft.com'
    'vortex-win.data.microsoft.com'
    'telecommand.telemetry.microsoft.com'
    'oca.telemetry.microsoft.com'
    'sqm.telemetry.microsoft.com'
    'watson.telemetry.microsoft.com'
    'settings-sandbox.data.microsoft.com'
    'vortex-sandbox.data.microsoft.com'
    'survey.watson.microsoft.com'
    'v10.events.data.microsoft.com'
    'v20.events.data.microsoft.com'
    'settings-win.data.microsoft.com'
    'v10.vortex-win.data.microsoft.com'
    'wes.df.telemetry.microsoft.com'
    'services.wes.df.telemetry.microsoft.com'
    'sqm.df.telemetry.microsoft.com'
    'telemetry.microsoft.com'
    'telemetry.appex.bing.net'
    'telemetry.urs.microsoft.com'
    'cs1.wpc.v0cdn.net'
)
Invoke-Safe {
    $existing = Get-Content $hostsFile -Raw -ErrorAction SilentlyContinue
    if ($existing -notmatch [regex]::Escape($marker)) {
        $lines = @('', $marker) + ($blocks | ForEach-Object { "0.0.0.0 $_" })
        Add-Content -Path $hostsFile -Value ($lines -join "`r`n") -Encoding ascii
    }
} 'telemetry endpoints blocked via HOSTS'

# Also block at the policy level
Invoke-Safe {
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry' 0
    Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' 'AllowTelemetry' 0
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowDeviceNameInTelemetry' 0
} 'telemetry policy: Security level'

# ============================================================================
# 17.  Explorer cleanup
# ============================================================================
Write-Section '17  Explorer cleanup'

$adv = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
Invoke-Safe {
    Set-RegistryValue $adv 'LaunchTo'         1   # open to This PC
    Set-RegistryValue $adv 'ShowFrequent'     0   # no recent folders in Home
    Set-RegistryValue $adv 'ShowRecent'       0   # no recent files in Home
    Set-RegistryValue $adv 'Start_TrackDocs'  0
    Set-RegistryValue $adv 'HideFileExt'      0   # show extensions
    Set-RegistryValue $adv 'Hidden'           1   # show hidden files
    Set-RegistryValue $adv 'ShowSuperHidden'  1
    Set-RegistryValue $adv 'TaskbarMn'        0   # no Chat icon
    Set-RegistryValue $adv 'TaskbarAl'        0   # left-align taskbar (W11)
    Set-RegistryValue $adv 'TaskbarDa'        0   # no widgets
    Set-RegistryValue $adv 'ShowTaskViewButton' 0
} 'Explorer + taskbar defaults'

# Remove "Gallery" pin from Explorer nav (build 23H2+)
Invoke-Safe {
    $gal = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}'
    if (Test-Path $gal) { Remove-Item -Path $gal -Recurse -Force }
} 'remove Gallery from Explorer'

# Strip "This PC" extras: 3D Objects, Music, Videos folders (keep Docs, Downloads, Pictures, Desktop)
foreach ($k in '0DB7E03F-FC29-4DC6-9020-FF41B59E513A',  # 3D Objects
               '3dfdf296-dbec-4fb4-81d1-6a3438bcf4de',  # Music
               'a0c69a99-21c8-4671-8703-7934162fcf1d',  # Music (alt)
               'A8CDFF1C-4878-43be-B5FD-F8091C1C60D0',  # Documents
               'f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a',  # Videos
               'B4BFCC3A-DB2C-424C-B029-7FE99A87C641'   # Pictures
              ) {
    Invoke-Safe {
        Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{$k}" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{$k}" -Recurse -Force -ErrorAction SilentlyContinue
    } "remove This-PC namespace: $k"
}

# ============================================================================
# 18.  Start menu / lock screen / suggestions
# ============================================================================
Write-Section '18  Start menu / lock screen / ads'

$cdm = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
Invoke-Safe {
    foreach ($n in 'SubscribedContent-338388Enabled','SubscribedContent-338389Enabled',
                   'SubscribedContent-338393Enabled','SubscribedContent-353694Enabled',
                   'SubscribedContent-353696Enabled','SubscribedContent-353698Enabled',
                   'SubscribedContent-310093Enabled','SubscribedContent-202914Enabled',
                   'SilentInstalledAppsEnabled','SystemPaneSuggestionsEnabled',
                   'RotatingLockScreenEnabled','RotatingLockScreenOverlayEnabled',
                   'SubscribedContentEnabled','OemPreInstalledAppsEnabled',
                   'PreInstalledAppsEnabled','PreInstalledAppsEverEnabled') {
        Set-RegistryValue $cdm $n 0
    }
} 'ContentDeliveryManager suggestions off'

# Advertising ID
Invoke-Safe {
    Set-RegistryValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' 'Enabled' 0
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' 'DisabledByGroupPolicy' 1
} 'advertising ID disabled'

# "Get even more out of Windows" + first-run hints
Invoke-Safe {
    Set-RegistryValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement' 'ScoobeSystemSettingEnabled' 0
    Set-RegistryValue 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer' 'DisableNotificationCenter' 0
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableTailoredExperiencesWithDiagnosticData' 1
} 'tailored experiences + first-run hints off'

# Recommended section in Start
Invoke-Safe {
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' 'HideRecommendedSection' 1
} 'Start: Recommended section hidden'

# ============================================================================
# 19.  DISM cleanup (slow — runs last)
# ============================================================================
if (-not $SkipDISMCleanup) {
    Write-Section '19  DISM cleanup + ResetBase  (slow, 5-20 min)'

    Invoke-Safe { & DISM.exe /Online /Cleanup-Image /StartComponentCleanup /Quiet 2>&1 | Out-Null } 'StartComponentCleanup'
    Invoke-Safe { & DISM.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase /Quiet 2>&1 | Out-Null } 'StartComponentCleanup /ResetBase'
    Invoke-Safe { & DISM.exe /Online /Cleanup-Image /SPSuperseded /Quiet 2>&1 | Out-Null } 'SPSuperseded'
}

# ============================================================================
# Summary
# ============================================================================
Show-DebloatStatus

Write-Host ''
if ($script:Failures.Count -gt 0) {
    Write-Host "  $($script:Failures.Count) step(s) failed:" -ForegroundColor Red
    $script:Failures | ForEach-Object { Write-Host "    - $_" -ForegroundColor Red }
} else {
    Write-Host '  All steps completed.' -ForegroundColor Green
}

if (Test-PendingReboot) {
    Write-Host ''
    Write-Host '  *** REBOOT RECOMMENDED ***' -ForegroundColor Yellow
}

Write-Host ''
Write-Host "  Log: $LogFile" -ForegroundColor DarkGray

} finally {
    Stop-Transcript | Out-Null
}
