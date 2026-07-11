@echo off
setlocal
cd /d "%~dp0"
set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
call "%VCVARS%" >nul
echo === MIDL /no_robust: NdrNoRobust.idl ===
midl /nologo /no_robust /env x64 NdrNoRobust.idl
if errorlevel 1 exit /b 1
echo === Done: NdrNoRobust_s.c is the non-robust oracle ===
endlocal
