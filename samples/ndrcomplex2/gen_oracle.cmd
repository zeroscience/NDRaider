@echo off
setlocal
cd /d "%~dp0"
set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
call "%VCVARS%" >nul
echo === MIDL: NdrComplex2.idl ===
midl /nologo /env x64 NdrComplex2.idl
if errorlevel 1 exit /b 1
echo === Done: NdrComplex2_s.c is the oracle ===
endlocal
