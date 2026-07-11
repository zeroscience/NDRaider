@echo off
rem Build the known-good MIDL RPC client (NTLM CONNECT auth) for isolating the
rem ndr-fuzz auth issue. Requires NdrTest_c.c (run build.cmd / MIDL first).
setlocal
cd /d "%~dp0"
set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
call "%VCVARS%" >nul

if not exist NdrTest_c.c (
    echo [!] NdrTest_c.c missing - run build.cmd first to generate MIDL stubs.
    exit /b 1
)

echo === CL: client_main + client stub + support -> NdrTestClient.exe ===
cl /nologo /W3 client_main.c NdrTest_c.c support.c ^
    /link rpcrt4.lib /OUT:NdrTestClient.exe
if errorlevel 1 exit /b 1
echo === Done: NdrTestClient.exe ===
endlocal
