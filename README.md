# yonlaptop-setup

Idempotent PowerShell bootstrap for **persistent full-system developer access
to a Windows 11 machine over Tailscale**. One file, no external dependencies
beyond Tailscale itself and a working internet connection for package
downloads.

## What it does

| Phase | Result |
| ----- | ------ |
| 1  | Power policy: never sleep / hibernate, lid + power button = nothing, no fast startup |
| 2  | Developer Mode, Win32 long paths, Explorer dev defaults, dev root tree |
| 3  | OpenSSH Server (key + password auth, pwsh as default shell) |
| 4  | PSRemoting / WinRM over **HTTPS** (self-signed cert) |
| 5  | Remote Desktop (NLA on, TLS layer) |
| 6  | WSL2, Hyper-V, Containers, VirtualMachinePlatform, Windows Sandbox |
| 7  | winget (verify) + scoop + chocolatey |
| 8  | Optional: standard dev tool bundle |
| 9  | Optional: reverse-engineering bundle |
| 10 | Defender path exclusions for the dev root (RT scan stays on globally) |
| 11 | SYSTEM scheduled task: every 10 min re-assert services + firewall scope |
| 12 | Optional: boot auto-login |

## Security model

All inbound dev/admin services (SSH, WinRM-HTTPS, RDP) are firewalled to the
Tailscale ranges only:

```
IPv4   100.64.0.0/10        Tailscale CGNAT block
IPv6   fd7a:115c:a1e0::/48  Tailscale ULA block
```

The default Windows firewall rules that allow these services from `Any` are
**disabled** — only the Tailscale-scoped variants remain. The persistence task
re-applies this scope every 10 minutes, so a Windows Update or third-party
installer can't silently widen access.

The machine is therefore:

- **Reachable** from any device on your tailnet
- **Unreachable** from the local LAN
- **Unreachable** from the public internet

## Quick start

On the target Windows 11 machine, in an elevated PowerShell session:

```powershell
# Download
Invoke-WebRequest `
    https://raw.githubusercontent.com/CapitalistCookie/yonlaptop-setup/main/yonlaptop-setup.ps1 `
    -OutFile $env:TEMP\yonlaptop-setup.ps1

# Allow it to run for this process only
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# Bootstrap (insert your own SSH public key)
& $env:TEMP\yonlaptop-setup.ps1 `
    -SSHAuthorizedKeys @('ssh-ed25519 AAAA... you@host') `
    -InstallDevTools -InstallReverseEngTools
```

After verifying that key-based SSH works from another tailnet device, lock
password auth off:

```powershell
& $env:TEMP\yonlaptop-setup.ps1 -DisablePasswordAuth
```

Read-only status check (changes nothing):

```powershell
& $env:TEMP\yonlaptop-setup.ps1 -Verify
```

## Parameters

| Parameter | Default | Notes |
| --------- | ------- | ----- |
| `-SSHAuthorizedKeys` | `@()` | Public keys to install for the `Administrators` group. |
| `-DevRoot` | `C:\Dev` | Created and Defender-excluded. Contains `src/tools/sandbox/samples/build`. |
| `-ExtraDefenderExclusions` | `@()` | Additional paths to add to Defender exclusion list. |
| `-DisablePasswordAuth` | off | SSH key-only. Run AFTER confirming key auth works. |
| `-EnableAutoLogin` + `-AutoLoginUser` / `-AutoLoginPassword` | off | INSECURE on a portable device — password stored plaintext in HKLM. Use Sysinternals Autologon for DPAPI-encrypted version instead. |
| `-InstallDevTools` | off | Standard dev bundle (git, vscode, python, node, rust, go, .NET, JDK, VS Build Tools, llvm, cmake, ninja, docker, sysinternals, ripgrep, fd, fzf, jq, uv, PowerToys, ...) |
| `-InstallReverseEngTools` | off | RE bundle (ghidra, x64dbg, cutter, Wireshark, HxD, DIE, dnSpyEx, ilspy, radare2, yara, pe-bear) |
| `-DisableDefenderRealTime` | off | Full RT disable. Only on a dedicated malware-analysis VM. Requires Tamper Protection off in Windows Security. |
| `-SkipWindowsFeatures` | off | Skip Hyper-V / WSL2 / Containers / Sandbox / VMP. |
| `-Verify` | off | Read-only status check. Changes nothing. |
| `-DryRun` | off | Print intended actions without applying. |

## Connecting from another tailnet device

```bash
ssh you@<tailnet-name>                  # opens a pwsh shell
mstsc /v:<tailnet-name>                 # RDP (Windows)
```

PowerShell remoting from another Windows host:

```powershell
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck
Enter-PSSession -ComputerName <tailnet-name> -UseSSL -Credential (Get-Credential) -SessionOption $so
```

## Verification

From another tailnet device:

```bash
nc -vz <tailscale-ip> 22 3389 5986       # SSH / RDP / WinRM-HTTPS — all open
nc -vz <local-lan-ip-of-target> 22       # should TIMEOUT — proves scope
```

On the laptop:

```powershell
.\yonlaptop-setup.ps1 -Verify
```

## Idempotence and persistence

- Safe to re-run any time. Every phase checks state first.
- A SYSTEM scheduled task (`DevAccess-EnsureServices`) runs at boot and every
  10 minutes — re-asserts that `sshd` / `WinRM` / `TermService` / `Tailscale`
  are running with `Automatic` startup and that the firewall rules are still
  scoped to the Tailscale ranges.
- Logs land in `C:\ProgramData\DevAccessSetup\`.

## Requires

- Windows 11 (or recent Windows 10)
- PowerShell 5.1+ (script works on the built-in 5.1; recommends installing 7)
- Tailscale already installed and logged in
- An elevated PowerShell session

## License

MIT — see [LICENSE](LICENSE).
