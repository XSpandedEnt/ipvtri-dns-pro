@echo off
setlocal EnableExtensions EnableDelayedExpansion
set "INSTALL_DIR=%USERPROFILE%\IPvTriDNS\PRO"

if not exist "%INSTALL_DIR%\ipvtri_dns_super_changer_PRO.py" (
  echo [!] IPvTri PRO is not installed at: %INSTALL_DIR%
  echo     Run install_ipvtri_dns_PRO.bat first.
  pause
  exit /b 1
)

cd /d "%INSTALL_DIR%"
set "CMD="
py -3.12 -V >nul 2>&1 && set "CMD=py -3.12"
if not defined CMD py -3.11 -V >nul 2>&1 && set "CMD=py -3.11"
if not defined CMD py -3.10 -V >nul 2>&1 && set "CMD=py -3.10"
if not defined CMD py -3 -V >nul 2>&1 && set "CMD=py -3"
if not defined CMD python -V >nul 2>&1 && set "CMD=python"
if not defined CMD ( echo [!] No Python found. Install 3.11+ and retry. & pause & exit /b 1 )

%CMD% -c "import pystray, PIL" 2>nul
if errorlevel 1 ( set "TRAY_FLAG=" & echo [!] Tray deps missing (pystray + Pillow). ) else set "TRAY_FLAG=--tray"

echo [>] Launching IPvTri+...
%CMD% -u ipvtri_dns_super_changer_PRO.py --log-level INFO --csv logs\ipvtri_dns.csv --enforce-doh %TRAY_FLAG%
echo.
pause
