@echo off
setlocal EnableExtensions EnableDelayedExpansion
echo IPvTri+ — Installing optional deps: pystray, Pillow, cryptography

set "CMD="
py -3.12 -V >nul 2>&1 && set "CMD=py -3.12"
if not defined CMD py -3.11 -V >nul 2>&1 && set "CMD=py -3.11"
if not defined CMD py -3.10 -V >nul 2>&1 && set "CMD=py -3.10"
if not defined CMD py -3 -V >nul 2>&1 && set "CMD=py -3"
if not defined CMD python -V >nul 2>&1 && set "CMD=python"
if not defined CMD ( echo [!] No Python found. Install 3.11+ and retry. & pause & exit /b 1 )

%CMD% -m ensurepip --upgrade >nul 2>&1
%CMD% -m pip install --upgrade pip
%CMD% -m pip install pystray Pillow cryptography
if errorlevel 1 ( echo [!] Installation failed. Try running as Administrator. & pause & exit /b 1 )
echo [✔] Optional dependencies installed.
pause
