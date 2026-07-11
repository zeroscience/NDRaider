# hailmary-vantage-elevated.ps1
#
# Runs the coverage-guided autopilot (ndr-fuzz hail-mary --live --cov) against the
# LIVE Lenovo Vantage RPC server. The rich host (VantageCoreAddin) runs elevated,
# so attaching a coverage debugger to it needs SeDebugPrivilege - this script
# self-elevates. Authorized use on YOUR OWN machine only.
#
# Right-click -> "Run with PowerShell", or: powershell -ExecutionPolicy Bypass -File .\hailmary-vantage-elevated.ps1

$ErrorActionPreference = 'Stop'

# --- self-elevate ---
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Host "Not elevated - relaunching as Administrator (accept the UAC prompt)..." -ForegroundColor Yellow
    Start-Process powershell -Verb RunAs -ArgumentList "-NoExit","-ExecutionPolicy","Bypass","-File","`"$PSCommandPath`""
    return
}

$repo = Split-Path -Parent $PSCommandPath
$fuzz = Join-Path $repo "target\release\ndr-fuzz.exe"
if (-not (Test-Path $fuzz)) {
    Write-Host "ndr-fuzz.exe not found - build first:  cargo build --release" -ForegroundColor Red
    Read-Host "Press Enter to close"; return
}

# Locate the x86 VantageRpcServer.dll (server stub for interface 8eefa2e8),
# version-independently.
$dll = Get-ChildItem "C:\Program Files (x86)\Lenovo\VantageService" -Recurse -Filter "VantageRpcServer.dll" -ErrorAction SilentlyContinue |
       Where-Object { $_.FullName -match '\\x86\\' } | Select-Object -First 1 -ExpandProperty FullName
if (-not $dll) {
    Write-Host "x86 VantageRpcServer.dll not found under Lenovo\VantageService" -ForegroundColor Red
    Read-Host "Press Enter to close"; return
}
Write-Host "target server DLL: $dll" -ForegroundColor Cyan

$loot = Join-Path $repo "loot-vantage"
$before = @(Get-Process | Where-Object { $_.ProcessName -match 'Vantage' } | Select-Object -ExpandProperty Id)
Write-Host "Vantage PIDs before: $($before -join ',')" -ForegroundColor Cyan
Write-Host ""

# --json: Vantage is "JSON-over-RPC", so fill the byte[] buffers with fuzzed JSON
#   (reaches the command handlers instead of bouncing off the JSON parser). If you
#   capture real Vantage requests, drop them (one .json each) in a folder and add
#   --seeds <folder> to mutate them instead of synthesizing.
# -v narrates every step; drop it to watch the animated spinner instead.
# Crashes save crash_*.bin (repro) + crash_*.txt (registers/backtrace) into $loot.
& $fuzz -v hail-mary "$dll" --live --cov --json --count 60 --out "$loot" --i-am-authorized

Write-Host ""
$after = @(Get-Process | Where-Object { $_.ProcessName -match 'Vantage' } | Select-Object -ExpandProperty Id)
Write-Host "Vantage PIDs after:  $($after -join ',')" -ForegroundColor Cyan
$gone = $before | Where-Object { $_ -notin $after }
if ($gone) {
    Write-Host ">>> Vantage process(es) GONE: $($gone -join ',')  = possible CRASH (check the report)" -ForegroundColor Red
} else {
    Write-Host ">>> all Vantage processes survived" -ForegroundColor Green
}
Write-Host "report: $loot\ndr-hailmary-report.md"
Write-Host ""
Read-Host "Done. Press Enter to close"
