@echo off
rem Generate the MIDL oracle (.c/.h) only - no DLL. We read the format-string
rem byte arrays + comments out of NdrComplex_s.c to learn the complex layouts.
setlocal
cd /d "%~dp0"

set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
call "%VCVARS%" >nul

echo === MIDL: NdrComplex.idl ===
midl /nologo /env x64 NdrComplex.idl
if errorlevel 1 exit /b 1
echo === Done: NdrComplex_s.c is the oracle ===
endlocal
