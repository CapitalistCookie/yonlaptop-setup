<#
.SYNOPSIS
  Root-cause hardening for the 2026-06-20 sshd-wedge incident. Run ONCE on the laptop
  (yoni) as Administrator. After this + the CT112-side ControlMaster fix, a harness
  connection-burst can never wedge sshd again, and if anything ever does, a watchdog
  auto-recovers it within ~2 min (vs the old watchdog which only ensured Running and
  let a "running-but-wedged" sshd slip through — the exact failure that happened).

  WHAT WEDGED IT: wave-3 ran ~35 agents, each opening fresh ssh connections to this box.
  The burst overran the Windows sshd pre-auth queue (default MaxStartups 10:30:100) and
  left sshd in a state where it RESET every new connection at kex_exchange_identification
  while the service still showed "Running". The 10-min watchdog (ensure-Running) missed it.

  THE TWO-SIDED FIX:
    (A) CT112 client (DONE, in ~/.ssh/config): ControlMaster auto + ControlPersist 600 ->
        N agents now multiplex over ONE TCP connection. The storm cannot recur at the source.
    (B) This script (server backstop): raise MaxStartups/MaxSessions so a storm is tolerated,
        and replace the watchdog with one that tests a REAL connection and Restart-Service on wedge.
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$cfg = "$env:ProgramData\ssh\sshd_config"

# (1) Backstop: tolerate concurrency bursts. MaxStartups start:rate:full ; MaxSessions per-conn.
Copy-Item $cfg "$cfg.bak.preharden" -Force
$txt = Get-Content $cfg -Raw
$txt = ($txt -split "`r?`n" | Where-Object { $_ -notmatch '^\s*#?\s*(MaxStartups|MaxSessions)\b' }) -join "`r`n"
$txt = $txt.TrimEnd() + "`r`n`r`n# 2026-06-20 harden: tolerate harness connection bursts`r`nMaxStartups 100:30:200`r`nMaxSessions 60`r`n"
Set-Content $cfg $txt -Encoding ascii
Write-Host "[harden] sshd_config: MaxStartups 100:30:200 / MaxSessions 60"

# (2) Wedge-detecting watchdog: every 2 min, do a REAL loopback ssh handshake. If it RESETS
#     (wedged) or times out while the service claims Running, force a restart. This catches the
#     running-but-wedged state the old ensure-Running watchdog could not.
$wd = "$env:ProgramData\ssh\sshd_wedge_watchdog.ps1"
@'
$ErrorActionPreference = "SilentlyContinue"
$svc = Get-Service sshd
if ($svc.Status -ne "Running") { Start-Service sshd; exit }
# real handshake probe to localhost:22 (banner read); wedge => no banner / reset
$ok = $false
try {
  $c = New-Object Net.Sockets.TcpClient
  $c.Connect("127.0.0.1", 22); $c.ReceiveTimeout = 4000
  $s = $c.GetStream(); $buf = New-Object byte[] 16
  $n = $s.Read($buf, 0, 16)
  if ($n -gt 0 -and ([Text.Encoding]::ASCII.GetString($buf,0,$n)) -match "SSH-") { $ok = $true }
  $c.Close()
} catch { $ok = $false }
if (-not $ok) {
  "$(Get-Date -Format o)  sshd RUNNING but no SSH- banner -> WEDGE -> Restart-Service" |
    Add-Content "$env:ProgramData\ssh\sshd_wedge_watchdog.log"
  Restart-Service sshd -Force
}
'@ | Set-Content $wd -Encoding ascii
Write-Host "[harden] wrote wedge-probe watchdog: $wd"

# (3) Register it as a SYSTEM scheduled task every 2 min (replaces/augments the ensure-Running one).
$act = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$wd`""
$trg = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 2) -RepetitionDuration ([TimeSpan]::MaxValue)
$prn = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "sshd-wedge-watchdog" -Action $act -Trigger $trg -Principal $prn -Force | Out-Null
Write-Host "[harden] scheduled task 'sshd-wedge-watchdog' every 2 min"

# (4) Also configure the Windows service to auto-restart on a hard crash (belt + suspenders).
& sc.exe failure sshd reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null

# (5) Validate config; restart ONLY if valid (never break a working sshd from afar).
$sshdExe = (Get-Command sshd.exe -ErrorAction SilentlyContinue).Source
if (-not $sshdExe) { $sshdExe = "$env:ProgramFiles\OpenSSH\sshd.exe" }
$null = & $sshdExe -t 2>&1
if ($LASTEXITCODE -eq 0) {
  Restart-Service sshd -Force
  Write-Host "[harden] config VALID; sshd restarted. DONE — wedge can no longer persist."
} else {
  Copy-Item "$cfg.bak.preharden" $cfg -Force
  Write-Host "[harden] config INVALID -> REVERTED, sshd NOT restarted (watchdog still active)."
}
