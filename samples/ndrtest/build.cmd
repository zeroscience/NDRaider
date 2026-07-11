@echo off
rem Build the NDR ground-truth DLL: MIDL -> C stubs -> DLL.
rem Run from anywhere; it cd's to its own directory.
setlocal
cd /d "%~dp0"

set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" (
    echo [!] vcvars64.bat not found at "%VCVARS%"
    exit /b 1
)
call "%VCVARS%" >nul

echo === MIDL: NdrTest.idl -> stubs + format strings ===
midl /nologo /env x64 NdrTest.idl
if errorlevel 1 exit /b 1

echo === CL: SERVER stub + impls + support -> NdrTest.dll ===
rem The server stub carries the MIDL_SERVER_INFO pointer chain that real RPC/DCOM
rem service binaries have (and that M2 walks). server_impl.c provides the method
rem bodies the dispatch table references.
cl /nologo /LD /W3 NdrTest_s.c server_impl.c support.c /link rpcrt4.lib /OUT:NdrTest.dll
if errorlevel 1 exit /b 1

echo === Done. Artifacts: ===
echo   NdrTest.dll        (scan target - SERVER side)
echo   NdrTest_s.c        (ORACLE: MIDL_SERVER_INFO + proc/type format strings)
echo   NdrTest.h          (generated header)
endlocal
