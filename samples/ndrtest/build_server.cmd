@echo off
rem Build the standalone NdrTest RPC server (ncacn_ip_tcp:49152) for safe local
rem fuzz-transport validation. Requires NdrTest_s.c (run build.cmd / MIDL first).
setlocal
cd /d "%~dp0"
set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
call "%VCVARS%" >nul

if not exist NdrTest_s.c (
    echo [!] NdrTest_s.c missing - run build.cmd first to generate MIDL stubs.
    exit /b 1
)

echo === CL: server_main + stub + impls -> NdrTestServer.exe ===
cl /nologo /W3 server_main.c NdrTest_s.c server_impl.c support.c ^
    /link rpcrt4.lib /OUT:NdrTestServer.exe
if errorlevel 1 exit /b 1
echo === Done: NdrTestServer.exe ===
endlocal
