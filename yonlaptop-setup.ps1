#Requires -RunAsAdministrator
#Requires -Version 5.1

<#
.SYNOPSIS
    Persistent full-system developer access on Windows 11 over Tailscale.

.DESCRIPTION
    Idempotent, self-contained bootstrap. All inbound admin/dev services are
    firewalled to the Tailscale ranges only:

        IPv4 100.64.0.0/10        (CGNAT block Tailscale uses)
        IPv6 fd7a:115c:a1e0::/48  (Tailscale ULA block)

    so they are unreachable from the local LAN or public internet.

    Phases:
       1  Power & sleep (never sleep / hibernate, lid + power-btn = nothing,
          no fast startup)
       2  Developer Mode + long paths + Explorer dev defaults
       3  OpenSSH Server (key + password auth, pwsh default shell)
       4  PSRemoting / WinRM over HTTPS (self-signed cert, Tailscale-only)
       5  Remote Desktop (NLA on, TLS, Tailscale-only)
       6  WSL2, Hyper-V, Containers, VirtualMachinePlatform, Windows Sandbox
          (Hyper-V/Sandbox auto-skip on Win11 Home)
       7  Package managers: winget (verify), scoop, chocolatey
       8  Dev tool bundle  (git, gh, vscode, pwsh, terminal, python, node,
          rust, go, .NET, Temurin JDK, VS Build Tools, llvm, cmake, ninja,
          docker, sysinternals, ripgrep, fd, fzf, jq, uv, PowerToys, ...)
       9  Reverse-engineering bundle (ghidra, x64dbg, cutter, Wireshark,
          HxD, DIE, dnSpyEx, ilspy, radare2, yara, pe-bear)
      10  Defender path exclusions (RT scan stays on globally)
      11  Persistence scheduled task — every 10 min re-asserts services up
          + firewall scope intact
      12  Optional auto-login

    Safe to re-run. Each step checks state first.

    Run `.\yonlaptop-setup.ps1 -Verify` to check current state without
    making any changes.

.PARAMETER SSHAuthorizedKeys
    Public keys (ed25519 / rsa / ecdsa) to install into the local Admin
    group's authorized_keys file. Strongly recommended.

.PARAMETER DevRoot
    Root dev / sandbox / RE directory. Created and Defender-excluded.

.PARAMETER ExtraDefenderExclusions
    Additional paths to add to Defender exclusion list.

.PARAMETER DisablePasswordAuth
    Lock SSH to key-only auth. Do this AFTER verifying key login works.

.PARAMETER EnableAutoLogin
    Configure boot auto-login. Stores password plaintext in HKLM — off by
    default. Use Sysinternals Autologon for DPAPI-encrypted version.

.PARAMETER AutoLoginUser
.PARAMETER AutoLoginPassword
    Required with -EnableAutoLogin.

.PARAMETER InstallDevTools
    Install the standard dev bundle via winget.

.PARAMETER InstallReverseEngTools
    Install the RE bundle via winget + scoop.

.PARAMETER DisableDefenderRealTime
    Disable Defender RT protection. Requires Tamper Protection off.
    Only on a dedicated malware-analysis VM, not your daily driver.

.PARAMETER SkipWindowsFeatures
    Skip Hyper-V / WSL2 / Containers / Sandbox / VMP feature enablement.

.PARAMETER Verify
    Read-only mode. Print status of every component, change nothing.

.PARAMETER DryRun
    Print intended actions without applying them.

.EXAMPLE
    # First-time bootstrap (recommended)
    .\yonlaptop-setup.ps1 `
        -SSHAuthorizedKeys @('ssh-ed25519 AAAA... you@host') `
        -InstallDevTools -InstallReverseEngTools

    # Confirm everything stuck
    .\yonlaptop-setup.ps1 -Verify

    # Lock down after key auth is confirmed
    .\yonlaptop-setup.ps1 -DisablePasswordAuth

.NOTES
    Version : 1.1.0
    Source  : https://github.com/CapitalistCookie/yonlaptop-setup
    License : MIT
    Run from an elevated PowerShell 5.1+ session. Reboot may be required
    after first run for WSL2 / Hyper-V; script reports pending-reboot state.
#>

[CmdletBinding()]
param(
    [string[]] $SSHAuthorizedKeys      = @(),
    [string]   $DevRoot                = 'C:\Dev',
    [string[]] $ExtraDefenderExclusions = @(),
    [switch]   $DisablePasswordAuth,
    [switch]   $EnableAutoLogin,
    [string]   $AutoLoginUser,
    [string]   $AutoLoginPassword,
    [switch]   $InstallDevTools,
    [switch]   $InstallReverseEngTools,
    [switch]   $DisableDefenderRealTime,
    [switch]   $SkipWindowsFeatures,
    [switch]   $Verify,
    [switch]   $DryRun
)

# ============================================================================
# Globals
# ============================================================================
$script:Version = '1.1.0'

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

$TS_V4 = '100.64.0.0/10'
$TS_V6 = 'fd7a:115c:a1e0::/48'
$TS_REMOTE = @($TS_V4, $TS_V6)

$LogDir  = Join-Path $env:ProgramData 'DevAccessSetup'
$LogFile = Join-Path $LogDir ("setup-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
$null = New-Item -ItemType Directory -Force -Path $LogDir

$script:Failures = @()

# ============================================================================
# Helpers
# ============================================================================
function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor Cyan
    Write-Host (" $Title") -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor Cyan
}

function Write-Step {
    param([string]$Msg, [ValidateSet('OK','WARN','FAIL','SKIP','INFO')]$Status='INFO')
    $color = @{ OK='Green'; WARN='Yellow'; FAIL='Red'; SKIP='DarkGray'; INFO='Gray' }[$Status]
    Write-Host (" [{0,-4}] {1}" -f $Status, $Msg) -ForegroundColor $color
}

function Invoke-Safe {
    param([scriptblock]$Block, [string]$What)
    if ($DryRun -or $Verify) { Write-Step "[skip] $What" 'SKIP'; return }
    try   { & $Block | Out-Null; Write-Step $What 'OK' }
    catch { Write-Step "$What  --  $($_.Exception.Message)" 'FAIL'
            $script:Failures += $What }
}

function Set-RegistryValue {
    param([string]$Path, [string]$Name, $Value, [string]$Type='DWord')
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    $existing = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -ne $existing -and ($existing.PSObject.Properties.Name -contains $Name)) {
        Set-ItemProperty -Path $Path -Name $Name -Value $Value
    } else {
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    }
}

function Test-PendingReboot {
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { return $true }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { return $true }
    $sm = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
            -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
    if ($sm) { return $true }
    return $false
}

function Get-TailscaleInterface {
    try {
        Get-NetAdapter -ErrorAction Stop | Where-Object {
            $_.InterfaceDescription -match 'Tailscale' -or $_.Name -match 'Tailscale'
        } | Select-Object -First 1
    } catch { $null }
}

function Get-TailscaleIPv4 {
    $a = Get-TailscaleInterface
    if (-not $a) { return $null }
    (Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object IPAddress -like '100.*' | Select-Object -First 1).IPAddress
}

function Get-WinEdition {
    try { (Get-WindowsEdition -Online -ErrorAction Stop).Edition } catch { 'Unknown' }
}

function Test-EditionSupportsHyperV {
    $e = Get-WinEdition
    return ($e -match 'Professional|Pro$|Enterprise|Education|ProEducation|ProWorkstation|Server')
}

function Install-WingetPkg {
    param([string]$Id)
    if ($DryRun -or $Verify) { Write-Step "[skip] winget install $Id" 'SKIP'; return }
    $wg = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $wg) { Write-Step "winget missing; cannot install $Id" 'FAIL'; return }
    $existing = & winget list --id $Id --exact 2>$null | Select-String -Pattern $Id -SimpleMatch
    if ($existing) { Write-Step "winget $Id already present" 'SKIP'; return }
    try {
        & winget install --id $Id --exact --silent `
            --accept-source-agreements --accept-package-agreements `
            --disable-interactivity 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { Write-Step "winget $Id" 'OK' }
        else { Write-Step "winget $Id (exit $LASTEXITCODE)" 'WARN' }
    } catch { Write-Step "winget $Id  --  $($_.Exception.Message)" 'FAIL' }
}

# Read-only inspector — used by -Verify and end-of-run summary
function Show-Status {
    Write-Section 'Status'

    $tsIf  = Get-TailscaleInterface
    $tsIp4 = Get-TailscaleIPv4
    $tsIfDisplay  = if ($tsIf)  { "$($tsIf.Name) (ifIndex=$($tsIf.ifIndex))" } else { 'NOT FOUND' }
    $tsIp4Display = if ($tsIp4) { $tsIp4 } else { 'NOT FOUND' }
    Write-Host ("  Tailscale interface : {0}" -f $tsIfDisplay)
    Write-Host ("  Tailscale IPv4      : {0}" -f $tsIp4Display)
    Write-Host ("  Windows edition     : {0}" -f (Get-WinEdition))
    Write-Host ''

    function Show-Service { param($n,$expectAuto=$true)
        $s = Get-Service -Name $n -ErrorAction SilentlyContinue
        if (-not $s) { Write-Host ("    {0,-14} : NOT INSTALLED" -f $n) -ForegroundColor Red; return }
        $okStatus = ($s.Status -eq 'Running')
        $okStart  = (-not $expectAuto) -or ($s.StartType -eq 'Automatic')
        $color = if ($okStatus -and $okStart) { 'Green' } else { 'Yellow' }
        Write-Host ("    {0,-14} : {1,-10}  startup={2}" -f $n,$s.Status,$s.StartType) -ForegroundColor $color
    }
    Write-Host '  Services:'
    Show-Service sshd
    Show-Service WinRM
    Show-Service TermService
    Show-Service Tailscale
    Write-Host ''

    function Show-FwRule { param($n)
        $r = Get-NetFirewallRule -Name $n -ErrorAction SilentlyContinue
        if (-not $r) { Write-Host ("    {0,-32} : NOT FOUND" -f $n) -ForegroundColor Red; return }
        $remote = ($r | Get-NetFirewallAddressFilter).RemoteAddress -join ','
        $scoped = ($remote -match '100\.64\.0\.0/10' -or $remote -match 'fd7a:115c:a1e0')
        $color  = if ($r.Enabled -eq 'True' -and $scoped) { 'Green' } else { 'Yellow' }
        Write-Host ("    {0,-32} : enabled={1}  remote={2}" -f $n,$r.Enabled,$remote) -ForegroundColor $color
    }
    Write-Host '  Firewall rules:'
    Show-FwRule 'OpenSSH-Server-In-TCP'
    Show-FwRule 'WinRM-HTTPS-Tailscale'
    Show-FwRule 'RemoteDesktop-UserMode-In-TCP'
    Show-FwRule 'RemoteDesktop-UserMode-In-UDP'
    Write-Host ''

    Write-Host '  Misc:'
    $lp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name LongPathsEnabled -ErrorAction SilentlyContinue).LongPathsEnabled
    Write-Host ("    LongPathsEnabled    : {0}" -f $lp)
    $dm = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock' -Name AllowDevelopmentWithoutDevLicense -ErrorAction SilentlyContinue).AllowDevelopmentWithoutDevLicense
    Write-Host ("    DeveloperMode       : {0}" -f $dm)
    $hb = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name HiberbootEnabled -ErrorAction SilentlyContinue).HiberbootEnabled
    Write-Host ("    FastStartup (0=off) : {0}" -f $hb)
    $task = Get-ScheduledTask -TaskName 'DevAccess-EnsureServices' -ErrorAction SilentlyContinue
    Write-Host ("    Persistence task    : {0}" -f ($(if ($task) { "registered ($($task.State))" } else { 'NOT FOUND' })))
    Write-Host ("    Pending reboot      : {0}" -f (Test-PendingReboot))
}

# ============================================================================
# Main — wrap in try/finally so Stop-Transcript always runs
# ============================================================================
Start-Transcript -Path $LogFile -Force | Out-Null
try {

Write-Section ("0  Preflight  (yonlaptop-setup.ps1 v{0})" -f $script:Version)

$identity   = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal  = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Must run as Administrator.'
}
Write-Step "Running as $($identity.Name) (admin)" 'OK'

$os = Get-CimInstance Win32_OperatingSystem
Write-Step "OS: $($os.Caption) build $($os.BuildNumber)" 'OK'
if ($os.BuildNumber -lt 22000) { Write-Step 'Not Windows 11 — proceeding anyway' 'WARN' }

$edition = Get-WinEdition
Write-Step "Edition: $edition" 'OK'
$hyperVOK = Test-EditionSupportsHyperV
if (-not $hyperVOK) { Write-Step 'Edition does not support Hyper-V / Sandbox — those features will be skipped' 'WARN' }

# Remote-session detection (don't lock yourself out)
$remoteSession = $false
if ($env:SSH_CONNECTION) {
    $remoteSession = $true
    Write-Step "Running over SSH from $env:SSH_CONNECTION — your client IP must be in Tailscale range, else this will disconnect you" 'WARN'
}
if ($env:SESSIONNAME -like 'RDP-*') {
    $remoteSession = $true
    Write-Step "Running over RDP (SESSIONNAME=$env:SESSIONNAME) — your client IP must be in Tailscale range, else this will disconnect you" 'WARN'
}

$tsIf = Get-TailscaleInterface
if ($tsIf) {
    $tsIp = Get-TailscaleIPv4
    Write-Step "Tailscale interface: $($tsIf.Name)  IP=$tsIp" 'OK'
} else {
    Write-Step 'Tailscale interface not detected — services will still be Tailscale-scoped by IP range' 'WARN'
}
$tsSvc = Get-Service -Name Tailscale -ErrorAction SilentlyContinue
if (-not $tsSvc)              { Write-Step 'Tailscale service not installed' 'WARN' }
elseif ($tsSvc.Status -ne 'Running') { Write-Step "Tailscale service exists but is $($tsSvc.Status)" 'WARN' }

Write-Step "Log file: $LogFile" 'INFO'
if ($DryRun) { Write-Step 'DRY-RUN mode — no changes will be applied' 'WARN' }

# Verify-only short-circuit
if ($Verify) {
    Show-Status
    Write-Host ''
    Write-Host '  (Verify mode — no changes applied.)' -ForegroundColor DarkGray
    return
}

# ============================================================================
# 1.  Power & sleep
# ============================================================================
Write-Section '1  Power & sleep policy'

Invoke-Safe { powercfg /change standby-timeout-ac 0   } 'standby AC = never'
Invoke-Safe { powercfg /change standby-timeout-dc 0   } 'standby DC = never'
Invoke-Safe { powercfg /change hibernate-timeout-ac 0 } 'hibernate AC = never'
Invoke-Safe { powercfg /change hibernate-timeout-dc 0 } 'hibernate DC = never'
Invoke-Safe { powercfg /change disk-timeout-ac 0      } 'disk sleep AC = never'
Invoke-Safe { powercfg /change disk-timeout-dc 0      } 'disk sleep DC = never'
Invoke-Safe { powercfg /change monitor-timeout-ac 30  } 'monitor AC = 30 min'
Invoke-Safe { powercfg /change monitor-timeout-dc 15  } 'monitor DC = 15 min'
Invoke-Safe { powercfg /hibernate off                 } 'hibernation disabled'

# Power button / lid close = do nothing (closed laptop stays online)
Invoke-Safe { powercfg /SetACValueIndex SCHEME_CURRENT SUB_BUTTONS PBUTTONACTION 0 } 'power btn AC = nothing'
Invoke-Safe { powercfg /SetDCValueIndex SCHEME_CURRENT SUB_BUTTONS PBUTTONACTION 0 } 'power btn DC = nothing'
Invoke-Safe { powercfg /SetACValueIndex SCHEME_CURRENT SUB_BUTTONS LIDACTION 0 }     'lid close AC = nothing'
Invoke-Safe { powercfg /SetDCValueIndex SCHEME_CURRENT SUB_BUTTONS LIDACTION 0 }     'lid close DC = nothing'
Invoke-Safe { powercfg /SetACValueIndex SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0 } 'sleep btn AC = nothing'
Invoke-Safe { powercfg /SetActive SCHEME_CURRENT } 'apply scheme'

# Disable Fast Startup (interferes with WSL2 / cold-boot reliability)
Invoke-Safe {
    Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' 'HiberbootEnabled' 0
} 'fast startup disabled'

# ============================================================================
# 2.  Developer Mode, long paths, Explorer defaults
# ============================================================================
Write-Section '2  Developer Mode / long paths / Explorer defaults'

Invoke-Safe {
    Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock' 'AllowDevelopmentWithoutDevLicense' 1
    Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock' 'AllowAllTrustedApps' 1
} 'Developer Mode enabled'

Invoke-Safe {
    Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' 'LongPathsEnabled' 1
} 'Win32 long paths enabled'

# Apply Explorer defaults to current user + the .DEFAULT hive (new-user template)
$explorerAdv = 'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
$targets = @(
    "HKCU:\$explorerAdv",
    "Registry::HKEY_USERS\.DEFAULT\$explorerAdv"
)
foreach ($p in $targets) {
    Invoke-Safe {
        if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
        Set-RegistryValue $p 'Hidden'          1   # show hidden files
        Set-RegistryValue $p 'HideFileExt'     0   # show file extensions
        Set-RegistryValue $p 'ShowSuperHidden' 1   # show OS hidden files
        Set-RegistryValue $p 'LaunchTo'        1   # Explorer opens to This PC
    } "Explorer defaults ($p)"
}

# Full path in Explorer title bar
Invoke-Safe {
    Set-RegistryValue 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState' 'FullPath' 1
} 'Explorer: full path in title bar'

# Create dev root
if (-not (Test-Path $DevRoot)) {
    Invoke-Safe { New-Item -ItemType Directory -Path $DevRoot -Force | Out-Null } "create $DevRoot"
}
foreach ($sub in 'src','tools','sandbox','samples','build') {
    $p = Join-Path $DevRoot $sub
    if (-not (Test-Path $p) -and -not $DryRun) {
        New-Item -ItemType Directory -Path $p -Force | Out-Null
    }
}

# ============================================================================
# 3.  OpenSSH Server
# ============================================================================
Write-Section '3  OpenSSH Server'

Invoke-Safe {
    $cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*' -ErrorAction Stop |
           Where-Object Name -like 'OpenSSH.Server*' | Select-Object -First 1
    if (-not $cap) { throw 'OpenSSH.Server capability not found' }
    if ($cap.State -ne 'Installed') {
        Add-WindowsCapability -Online -Name $cap.Name -ErrorAction Stop | Out-Null
    }
} 'install OpenSSH.Server capability'

# The FOD post-install action that registers the sshd service is asynchronous
# and sometimes races us. Wait briefly, then fall back to install-sshd.ps1.
Invoke-Safe {
    $tries = 0
    while (-not (Get-Service sshd -ErrorAction SilentlyContinue) -and $tries -lt 10) {
        Start-Sleep -Seconds 2; $tries++
    }
    if (-not (Get-Service sshd -ErrorAction SilentlyContinue)) {
        $installSshd = Join-Path $env:WINDIR 'System32\OpenSSH\install-sshd.ps1'
        if (Test-Path $installSshd) {
            & $installSshd | Out-Null
        } elseif (Test-Path "$env:WINDIR\System32\OpenSSH\sshd.exe") {
            New-Service -Name sshd `
                -BinaryPathName "$env:WINDIR\System32\OpenSSH\sshd.exe" `
                -DisplayName 'OpenSSH SSH Server' `
                -StartupType Automatic | Out-Null
        } else {
            throw 'sshd.exe not found - OpenSSH.Server capability install incomplete'
        }
    }
} 'sshd service registration'

Invoke-Safe { Set-Service -Name sshd -StartupType Automatic } 'sshd auto-start'
Invoke-Safe { Start-Service sshd } 'sshd running'

# Default shell = pwsh if present, else powershell
$pwshPath = (Get-Command pwsh.exe -ErrorAction SilentlyContinue).Source
if (-not $pwshPath) { $pwshPath = (Get-Command powershell.exe).Source }
Invoke-Safe {
    Set-RegistryValue 'HKLM:\SOFTWARE\OpenSSH' 'DefaultShell' $pwshPath 'String'
} "default SSH shell = $pwshPath"

# Generate a clean sshd_config from a template (preserves admin Match block)
$sshdConfig = Join-Path $env:ProgramData 'ssh\sshd_config'
if (Test-Path $sshdConfig) {
    Invoke-Safe {
        Copy-Item $sshdConfig "$sshdConfig.bak-$(Get-Date -Format 'yyyyMMddHHmmss')" -Force
    } 'backup existing sshd_config'
}

$passLine = if ($DisablePasswordAuth) { 'PasswordAuthentication no' } else { 'PasswordAuthentication yes' }
$sshdBody = @"
# Generated by yonlaptop-setup.ps1 v$($script:Version) on $(Get-Date -Format o)
Port 22
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::

PubkeyAuthentication yes
$passLine
PermitRootLogin no
PermitEmptyPasswords no

ChallengeResponseAuthentication no
UsePAM no

X11Forwarding no
AllowAgentForwarding yes
AllowTcpForwarding yes
GatewayPorts no

ClientAliveInterval 60
ClientAliveCountMax 5

LogLevel INFO
SyslogFacility AUTH

Subsystem sftp sftp-server.exe

# Admin users authenticate via the machine-wide admin keys file
Match Group administrators
       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
"@
Invoke-Safe {
    Set-Content -Path $sshdConfig -Value $sshdBody -Encoding ascii -Force
} 'sshd_config written'

# Install authorized keys for the Administrators group
if ($SSHAuthorizedKeys.Count -gt 0) {
    $adminKeys = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
    Invoke-Safe {
        $SSHAuthorizedKeys | Set-Content -Path $adminKeys -Encoding ascii
        & icacls.exe $adminKeys /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F' | Out-Null
    } "install $($SSHAuthorizedKeys.Count) key(s) -> administrators_authorized_keys"
} else {
    Write-Step 'No SSH keys provided — password auth only. Add -SSHAuthorizedKeys ASAP.' 'WARN'
}

Invoke-Safe { Restart-Service sshd } 'sshd restart'

# Firewall: scope OpenSSH to Tailscale
Invoke-Safe {
    $r = Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue
    if ($r) {
        $r | Set-NetFirewallRule -RemoteAddress $TS_REMOTE -Enabled True -Profile Any -Action Allow
    } else {
        New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' `
            -DisplayName 'OpenSSH SSH Server (Tailscale)' `
            -Direction Inbound -Protocol TCP -LocalPort 22 `
            -RemoteAddress $TS_REMOTE -Action Allow -Profile Any | Out-Null
    }
} 'sshd firewall rule -> Tailscale only'

# ============================================================================
# 4.  PowerShell Remoting / WinRM over HTTPS
# ============================================================================
Write-Section '4  WinRM / PSRemoting (HTTPS, Tailscale-only)'

Invoke-Safe { Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null } 'Enable-PSRemoting'

# Self-signed cert (SSL server EKU) for HTTPS listener
$cn = $env:COMPUTERNAME
$cert = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -eq "CN=$cn" -and $_.NotAfter -gt (Get-Date).AddDays(30) -and
                       $_.EnhancedKeyUsageList.FriendlyName -contains 'Server Authentication' } |
        Select-Object -First 1
if (-not $cert -and -not ($DryRun -or $Verify)) {
    try {
        $cert = New-SelfSignedCertificate -DnsName $cn `
                    -CertStoreLocation Cert:\LocalMachine\My `
                    -Type SSLServerAuthentication `
                    -KeyUsage DigitalSignature,KeyEncipherment `
                    -KeyAlgorithm RSA -KeyLength 2048 `
                    -NotAfter (Get-Date).AddYears(3)
        Write-Step "self-signed cert created  thumbprint=$($cert.Thumbprint)" 'OK'
    } catch {
        Write-Step "cert create failed: $($_.Exception.Message)" 'FAIL'
        $script:Failures += 'self-signed cert'
    }
}

if ($cert) {
    Invoke-Safe {
        Get-ChildItem WSMan:\localhost\Listener -ErrorAction SilentlyContinue |
            Where-Object { $_.Keys -match 'Transport=HTTPS' } |
            ForEach-Object { Remove-Item -Recurse -Path $_.PSPath -Force }
        New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * `
            -CertificateThumbPrint $cert.Thumbprint -Force | Out-Null
    } 'WinRM HTTPS listener (5986)'

    Invoke-Safe {
        Get-ChildItem WSMan:\localhost\Listener -ErrorAction SilentlyContinue |
            Where-Object { $_.Keys -match 'Transport=HTTP$' } |
            ForEach-Object { Remove-Item -Recurse -Path $_.PSPath -Force }
    } 'WinRM HTTP listener removed'

    # Disable the default WinRM firewall rules (allow from Any) by Name pattern
    Invoke-Safe {
        Get-NetFirewallRule -Name 'WINRM-*' -ErrorAction SilentlyContinue | Disable-NetFirewallRule
    } 'default WinRM firewall rules disabled'

    Invoke-Safe {
        $existing = Get-NetFirewallRule -Name 'WinRM-HTTPS-Tailscale' -ErrorAction SilentlyContinue
        if ($existing) { Remove-NetFirewallRule -Name 'WinRM-HTTPS-Tailscale' }
        New-NetFirewallRule -Name 'WinRM-HTTPS-Tailscale' `
            -DisplayName 'WinRM HTTPS (Tailscale)' `
            -Direction Inbound -Protocol TCP -LocalPort 5986 `
            -RemoteAddress $TS_REMOTE -Action Allow -Profile Any | Out-Null
    } 'WinRM HTTPS firewall rule -> Tailscale only'
}

Invoke-Safe { Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false -Force } 'WinRM: encryption required'
Invoke-Safe { Set-Item WSMan:\localhost\MaxTimeoutms             -Value 1800000 -Force } 'WinRM: 30 min timeout'

# ============================================================================
# 5.  Remote Desktop
# ============================================================================
Write-Section '5  Remote Desktop'

Invoke-Safe {
    Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' 0
} 'RDP enabled'

Invoke-Safe {
    Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication' 1
} 'RDP NLA on'

Invoke-Safe {
    Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'SecurityLayer' 2
} 'RDP TLS security layer'

# Scope RDP firewall by Name (not localized DisplayGroup)
foreach ($n in 'RemoteDesktop-UserMode-In-TCP','RemoteDesktop-UserMode-In-UDP','RemoteDesktop-Shadow-In-TCP') {
    Invoke-Safe {
        $r = Get-NetFirewallRule -Name $n -ErrorAction SilentlyContinue
        if ($r) { $r | Set-NetFirewallRule -RemoteAddress $TS_REMOTE -Enabled True -Profile Any -Action Allow }
    } "RDP firewall: $n -> Tailscale only"
}

Invoke-Safe { Set-Service -Name TermService -StartupType Automatic } 'TermService auto-start'
Invoke-Safe { Start-Service TermService } 'TermService running'

# ============================================================================
# 6.  Windows features (WSL2, Hyper-V, Containers, Sandbox, VMP)
# ============================================================================
if (-not $SkipWindowsFeatures) {
    Write-Section '6  Windows features'

    $features = @(
        @{ Name='Microsoft-Windows-Subsystem-Linux'; Req='Any'  },
        @{ Name='VirtualMachinePlatform';            Req='Any'  },
        @{ Name='Microsoft-Hyper-V-All';             Req='Pro'  },
        @{ Name='Containers';                        Req='Pro'  },
        @{ Name='Containers-DisposableClientVM';     Req='Pro'  }
    )
    foreach ($f in $features) {
        if ($f.Req -eq 'Pro' -and -not $hyperVOK) {
            Write-Step "feature $($f.Name) skipped (requires Pro/Enterprise)" 'SKIP'
            continue
        }
        Invoke-Safe {
            $state = (Get-WindowsOptionalFeature -Online -FeatureName $f.Name -ErrorAction SilentlyContinue).State
            if ($state -ne 'Enabled') {
                Enable-WindowsOptionalFeature -Online -FeatureName $f.Name -All -NoRestart -ErrorAction Stop | Out-Null
            }
        } "feature: $($f.Name)"
    }

    # WSL kernel + default v2
    Invoke-Safe {
        $null = & wsl --status 2>&1
        if ($LASTEXITCODE -ne 0) { & wsl --install --no-distribution 2>&1 | Out-Null }
        & wsl --set-default-version 2 2>&1 | Out-Null
    } 'WSL2 base install + default v2'
} else {
    Write-Section '6  Windows features (skipped via -SkipWindowsFeatures)'
}

# ============================================================================
# 7.  Package managers
# ============================================================================
Write-Section '7  Package managers'

$winget = Get-Command winget -ErrorAction SilentlyContinue
if (-not $winget) {
    Write-Step 'winget missing — install "App Installer" from Microsoft Store, then re-run' 'WARN'
} else {
    Write-Step "winget present: $((& winget --version) 2>&1)" 'OK'
}

# scoop — requires explicit consent to run elevated
if (-not (Get-Command scoop -ErrorAction SilentlyContinue)) {
    Invoke-Safe {
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
        Invoke-Expression "& {$(Invoke-RestMethod -UseBasicParsing https://get.scoop.sh)} -RunAsAdmin"
    } 'scoop install (elevated, -RunAsAdmin)'
} else { Write-Step 'scoop already installed' 'SKIP' }

# chocolatey
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Invoke-Safe {
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
        [Net.ServicePointManager]::SecurityProtocol =
            [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        Invoke-Expression ((New-Object Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    } 'chocolatey install'
} else { Write-Step 'chocolatey already installed' 'SKIP' }

# ============================================================================
# 8.  Standard dev tool bundle
# ============================================================================
if ($InstallDevTools) {
    Write-Section '8  Dev tools (winget)'

    $devPackages = @(
        # shell & editors
        'Microsoft.PowerShell',
        'Microsoft.WindowsTerminal',
        'Microsoft.VisualStudioCode',
        'Notepad++.Notepad++',
        'Neovim.Neovim',
        # vcs
        'Git.Git',
        'GitHub.cli',
        # languages
        'Python.Python.3.12',
        'OpenJS.NodeJS.LTS',
        'Rustlang.Rustup',
        'GoLang.Go',
        'Microsoft.DotNet.SDK.8',
        'EclipseAdoptium.Temurin.21.JDK',
        # build
        'Microsoft.VisualStudio.2022.BuildTools',
        'Kitware.CMake',
        'Ninja-build.Ninja',
        'LLVM.LLVM',
        # containers / VMs
        'Docker.DockerDesktop',
        # utilities
        '7zip.7zip',
        'Microsoft.Sysinternals.Suite',
        'voidtools.Everything',
        'WinDirStat.WinDirStat',
        'gerardog.gsudo',
        'JanDeDobbeleer.OhMyPosh',
        'sharkdp.bat',
        'sharkdp.fd',
        'BurntSushi.ripgrep.MSVC',
        'junegunn.fzf',
        'jqlang.jq',
        'astral-sh.uv',
        'Microsoft.PowerToys'
    )
    foreach ($p in $devPackages) { Install-WingetPkg $p }
} else {
    Write-Section '8  Dev tools (skipped — pass -InstallDevTools to enable)'
}

# ============================================================================
# 9.  Reverse-engineering bundle
# ============================================================================
if ($InstallReverseEngTools) {
    Write-Section '9  Reverse-engineering tools'

    $rePackages = @(
        'NationalSecurityAgency.Ghidra',
        'x64dbg.x64dbg',
        'RizinOrg.Cutter',
        'WiresharkFoundation.Wireshark',
        'MaelHorz.HxD',
        'horsicq.DetectItEasy',
        'dnSpyEx.dnSpy',
        'WinMerge.WinMerge'
    )
    foreach ($p in $rePackages) { Install-WingetPkg $p }

    # Scoop extras for tools not in winget
    Invoke-Safe {
        & scoop bucket add extras  2>$null
        & scoop bucket add nirsoft 2>$null
        & scoop install pe-bear ilspy radare2 yara 2>&1 | Out-Null
    } 'scoop extras: pe-bear, ilspy, radare2, yara'

    Write-Step 'IDA Free: download manually from https://hex-rays.com/ida-free/ (no silent installer)' 'INFO'
} else {
    Write-Section '9  RE tools (skipped — pass -InstallReverseEngTools to enable)'
}

# ============================================================================
# 10.  Defender exclusions
# ============================================================================
Write-Section '10  Windows Defender'

$exclusions = @($DevRoot) + $ExtraDefenderExclusions
foreach ($p in $exclusions) {
    Invoke-Safe { Add-MpPreference -ExclusionPath $p -ErrorAction Stop } "exclude path: $p"
}

Invoke-Safe { Set-MpPreference -SubmitSamplesConsent 2 } 'never submit samples'
Invoke-Safe { Set-MpPreference -MAPSReporting 0 }        'MAPS reporting off'

if ($DisableDefenderRealTime) {
    Write-Step 'Disabling Defender real-time (Tamper Protection must be off in Windows Security)' 'WARN'
    Invoke-Safe { Set-MpPreference -DisableRealtimeMonitoring $true } 'RT protection disabled'
}

# ============================================================================
# 11.  Persistence scheduled task
# ============================================================================
Write-Section '11  Persistence task'

$persistScript = Join-Path $LogDir 'ensure-services.ps1'
$persistBody = @'
# Auto-generated. Re-asserts dev-access services + Tailscale firewall scope.
$ErrorActionPreference = 'SilentlyContinue'
foreach ($s in 'sshd','WinRM','TermService','Tailscale') {
    $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Running') { Start-Service -Name $s }
    if ($svc -and $svc.StartType -ne 'Automatic') { Set-Service -Name $s -StartupType Automatic }
}
$TS = @('100.64.0.0/10','fd7a:115c:a1e0::/48')
foreach ($n in 'OpenSSH-Server-In-TCP','WinRM-HTTPS-Tailscale',
               'RemoteDesktop-UserMode-In-TCP','RemoteDesktop-UserMode-In-UDP',
               'RemoteDesktop-Shadow-In-TCP') {
    $r = Get-NetFirewallRule -Name $n -ErrorAction SilentlyContinue
    if ($r) { $r | Set-NetFirewallRule -RemoteAddress $TS -Enabled True -Action Allow }
}
# Re-disable the default WinRM Any-allow rules in case Windows re-enabled them
Get-NetFirewallRule -Name 'WINRM-*' -ErrorAction SilentlyContinue | Disable-NetFirewallRule
'@
if (-not ($DryRun -or $Verify)) {
    Set-Content -Path $persistScript -Value $persistBody -Encoding utf8 -Force
    Write-Step "persistence script: $persistScript" 'OK'
}

Invoke-Safe {
    $taskName = 'DevAccess-EnsureServices'
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    $action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
                -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$persistScript`""
    $tr1     = New-ScheduledTaskTrigger -AtStartup
    $tr2     = New-ScheduledTaskTrigger -Once -At ([DateTime]::Now.AddMinutes(1)) `
                  -RepetitionInterval (New-TimeSpan -Minutes 10)
    $prin    = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                  -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger @($tr1,$tr2) `
                  -Principal $prin -Settings $settings `
                  -Description 'Keep dev-access services healthy and firewall scoped to Tailscale' | Out-Null
} 'persistence scheduled task registered'

# ============================================================================
# 12.  Optional auto-login
# ============================================================================
if ($EnableAutoLogin) {
    Write-Section '12  Auto-login (WARNING: registry stores password in plaintext)'
    if (-not $AutoLoginUser -or -not $AutoLoginPassword) {
        Write-Step 'AutoLoginUser/AutoLoginPassword not supplied — skipping' 'FAIL'
    } else {
        $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        Invoke-Safe {
            Set-RegistryValue $wl 'AutoAdminLogon'    '1'              'String'
            Set-RegistryValue $wl 'DefaultUserName'   $AutoLoginUser   'String'
            Set-RegistryValue $wl 'DefaultDomainName' '.'              'String'
            Set-RegistryValue $wl 'DefaultPassword'   $AutoLoginPassword 'String'
            Set-RegistryValue $wl 'ForceAutoLogon'    '1'              'String'
        } 'auto-login registry keys'
        Write-Step 'Prefer Sysinternals Autologon (DPAPI-encrypted) over this method.' 'WARN'
    }
} else {
    Write-Section '12  Auto-login skipped (pass -EnableAutoLogin to enable)'
}

# ============================================================================
# Summary
# ============================================================================
Show-Status

Write-Host ''
Write-Host '  ---- Connect to this machine ----' -ForegroundColor White
Write-Host ''
$tsIp4 = Get-TailscaleIPv4
if ($tsIp4) {
    Write-Host "    Tailscale IPv4 : $tsIp4"
    Write-Host "    Hostname       : $env:COMPUTERNAME"
    Write-Host ''
    Write-Host "    SSH            : ssh $env:USERNAME@$tsIp4"
    Write-Host "    RDP            : mstsc /v:$tsIp4"
    Write-Host "    WinRM (HTTPS)  : Enter-PSSession -ComputerName $tsIp4 -UseSSL -Credential (Get-Credential) ``"
    Write-Host "                       -SessionOption (New-PSSessionOption -SkipCACheck -SkipCNCheck)"
} else {
    Write-Host '    (no Tailscale IPv4 — connect via your tailnet hostname/MagicDNS)'
}
Write-Host ''
if ($script:Failures.Count -gt 0) {
    Write-Host "  $($script:Failures.Count) step(s) failed:" -ForegroundColor Red
    $script:Failures | ForEach-Object { Write-Host "    - $_" -ForegroundColor Red }
} else {
    Write-Host '  All steps completed successfully.' -ForegroundColor Green
}
if (Test-PendingReboot) {
    Write-Host ''
    Write-Host '  *** REBOOT PENDING (WSL2 / Hyper-V / feature changes) ***' -ForegroundColor Yellow
    Write-Host '      Run: Restart-Computer -Force' -ForegroundColor Yellow
}
Write-Host ''
Write-Host "  Log: $LogFile" -ForegroundColor DarkGray
Write-Host ''

} finally {
    Stop-Transcript | Out-Null
}
