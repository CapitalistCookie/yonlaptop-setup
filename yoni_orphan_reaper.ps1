# toxicflow orphan-reaper (yoni). Root-cause fix for the 2026-06-20 leftover-process / high-CPU incident:
# a harness build agent ended (verdict NEEDS-DATA / timeout) but its DETACHED multiprocessing backtest
# kept running -> 8 worker python pegged 8 cores for 46+ min. The build script's _slots release never ran,
# so the slot stayed "held" too. The old yonlaptop watchdog only watched sshd, not orphaned research python.
#
# KILL CRITERION = CPU-TIME, not command-line: multiprocessing WORKERS carry a spawn-bootstrap command line
# (no script path), so a path/name filter misses them. But a python process accumulating >45 min of CPU is
# an orphaned backtest with certainty -- NO legit toxicflow build runs its python that long (the heaviest,
# MKSHP's full battery, is ~25 min). So CPU>2700s is safe (never kills a live build) and catches every orphan.
# Runs every 10 min via a SYSTEM scheduled task -> an orphan is reaped within ~10 min of crossing the line,
# bounding waste to ~55 min instead of forever.
$ErrorActionPreference = "SilentlyContinue"
$log  = "C:/Dev/research_out/_reaper.log"
$slots = "C:/Dev/research_out/_slots"

# 1. reap orphaned research python (CPU-time > 45 min)
foreach ($p in (Get-Process python -ErrorAction SilentlyContinue | Where-Object { $_.CPU -gt 2700 })) {
  "$(Get-Date -Format o)  REAP orphan python pid $($p.Id) cpu=$([math]::Round($p.CPU))s ws=$([math]::Round($p.WorkingSet64/1MB))MB" | Add-Content $log
  Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
}
# 2. clear stale _slots (held > 60 min -> a real build released long ago; an orphan left it behind)
foreach ($s in (Get-ChildItem "$slots/*.slot" -ErrorAction SilentlyContinue | Where-Object { ((Get-Date) - $_.LastWriteTime).TotalMinutes -gt 60 })) {
  "$(Get-Date -Format o)  REAP stale slot $($s.Name)" | Add-Content $log
  Remove-Item $s.FullName -Force -ErrorAction SilentlyContinue
}
