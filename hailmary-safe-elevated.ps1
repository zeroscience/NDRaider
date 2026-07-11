# hailmary-safe-elevated.ps1
#
# Coverage-GUIDED autopilot (ndr-fuzz hail-mary --live --cov) against a CURATED,
# NON-CRITICAL set of local Windows RPC services. Running elevated lets the
# coverage debugger attach to the SYSTEM-hosted x64 services (SeDebugPrivilege),
# so you get real basic-block coverage feedback instead of blind fuzzing.
#
# SAFETY: this only ever fuzzes interfaces extracted from the allow-listed host
# DLLs below. The known machine-killers (lsass family, SCM/services.exe, power,
# shutdown, firewall, UAC broker, RPCSS) are NEVER copied, so they are never
# bind-matched or touched. A crash in an allow-listed service is a recoverable
# service restart, not a reboot. Authorized use on YOUR OWN machine only.
#
# Right-click -> "Run with PowerShell", or:
#   powershell -ExecutionPolicy Bypass -File .\hailmary-safe-elevated.ps1

$ErrorActionPreference = 'Stop'

# --- self-elevate (coverage attach to SYSTEM services needs SeDebugPrivilege) ---
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

# --- ALLOW-LIST: non-critical service hosts only. A crash here = recoverable ---
# --- service restart. NEVER add lsass/samsrv/scesrv/keyiso/vaultsvc, services  ---
# --- .exe, umpo, wininit, rpcss, mpssvc/bfe, appinfo.                          ---
$allow = @(
  # audio
  'audiodg.exe','audiosrv.dll','audioeng.dll','AudioSes.dll',
  # device association / still image / sensors / telephony
  'das.dll','deviceassociation.dll','wiaservc.dll','wiarpc.dll','sti.dll',
  'SensorService.dll','tapisrv.dll','unimdm.tsp','unimdmat.dll',
  # networking helpers / vpn / event log / link tracking / notifications
  'iphlpsvc.dll','SstpSvc.dll','wevtsvc.dll','trkwks.dll','sens.dll',
  'dnsrslvr.dll','wcmsvc.dll','wecsvc.dll','wpnservice.dll',
  # scheduling / update / bits / time / storage / cdp / themes / discovery
  'schedsvc.dll','wuaueng.dll','qmgr.dll','w32time.dll','storsvc.dll',
  'cdpsvc.dll','themeservice.dll','fdPHost.dll','fdrespub.dll','fundisc.dll',
  # wlan / bluetooth / superfetch / user manager / data sharing
  'wlansvc.dll','wlanmsm.dll','bthserv.dll','BluetoothApis.dll',
  'SysMain.dll','usermgr.dll','DsSvc.dll','CDPUserSvc.dll',
  # print
  'spoolsv.exe','localspl.dll','spoolss.dll'
)

$hosts = Join-Path $repo "loot-safe\hosts"
New-Item -ItemType Directory -Force $hosts | Out-Null
Get-ChildItem $hosts -File -ErrorAction SilentlyContinue | Remove-Item -Force
$copied = 0
foreach ($n in $allow) {
    $p = Join-Path "C:\Windows\System32" $n
    if (Test-Path $p -PathType Leaf) {
        Copy-Item $p $hosts -Force -ErrorAction SilentlyContinue
        if ($?) { $copied++ }
    }
}
Write-Host "curated $copied non-critical host binary(ies) into $hosts" -ForegroundColor Cyan

$loot = Join-Path $repo "loot-safe"
# Health snapshot of the services we might exercise (so we can prove they survived).
$svc = 'Audiosrv','AudioEndpointBuilder','DeviceAssociationService','SensorService',
       'TapiSrv','TrkWks','EventLog','SstpSvc','stisvc','iphlpsvc','Spooler','Schedule',
       'BITS','W32Time','WlanSvc','bthserv','StorSvc','CDPSvc','Dnscache','Wecsvc',
       'Themes','wuauserv','SysMain','wpnservice'
$before = Get-Service $svc -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' } | Select-Object -ExpandProperty Name
Write-Host "running before: $($before.Count) service(s)" -ForegroundColor Cyan
Write-Host ""

# --cov: elevated, so the debugger CAN attach to these SYSTEM x64 services and
#        collect real basic-block coverage (WOW64 targets stay crash-detect only).
# -v narrates each attach/instrument/fuzz step; drop it for the animated spinner.
& $fuzz -v hail-mary "$hosts" --live --cov --count 25 --out "$loot" --i-am-authorized

Write-Host ""
Write-Host "=== service health after ===" -ForegroundColor Cyan
$after = Get-Service $svc -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' } | Select-Object -ExpandProperty Name
$dead = $before | Where-Object { $_ -notin $after }
if ($dead) {
    Write-Host ">>> service(s) NO LONGER RUNNING: $($dead -join ',')  = possible CRASH (check the report)" -ForegroundColor Red
} else {
    Write-Host ">>> all $($before.Count) service(s) still running" -ForegroundColor Green
}
Write-Host "report:  $loot\ndr-hailmary-report.md"
Write-Host "crashes: $loot\crash_*.bin / .txt (if any)"
Write-Host ""
Read-Host "Done. Press Enter to close"
