@echo off
rem Build a DLL-hosted RPC server (NdrTestSvc.dll) + a host exe (NdrTestHost.exe)
rem to validate cov-fuzz --module (instrumenting a DLL loaded by a host process).
rem Requires NdrTest_s.c (run build.cmd first).
setlocal
cd /d "%~dp0"
set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
call "%VCVARS%" >nul

if not exist NdrTest_s.c (
    echo [!] NdrTest_s.c missing - run build.cmd first to generate MIDL stubs.
    exit /b 1
)

echo === CL: RPC server in a DLL -> NdrTestSvc.dll ===
cl /nologo /LD /W3 dll_svc.c NdrTest_s.c server_impl.c support.c ^
    /link rpcrt4.lib /OUT:NdrTestSvc.dll
if errorlevel 1 exit /b 1

echo === CL: host process -> NdrTestHost.exe ===
cl /nologo /W3 host_main.c /Fe:NdrTestHost.exe
if errorlevel 1 exit /b 1

echo === Done: NdrTestHost.exe + NdrTestSvc.dll (ncalrpc:ndrtestdll) ===
endlocal
