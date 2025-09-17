@echo off
set "INSTALL_DIR=%USERPROFILE%\IPvTriDNS\PRO"
set "PY=py -3.11"
if not exist "%INSTALL_DIR%\ipvtri_dns_super_changer_PRO.py" (
  echo [!] Not installed at %INSTALL_DIR%. Run the installer.
  pause
  exit /b 1
)
cd /d "%INSTALL_DIR%"
where %PY% >nul 2>&1
if errorlevel 1 set "PY=python"
echo Starting IPvTri+ DNS (SAFE MODE)...
%PY% ipvtri_dns_super_changer_PRO.py --log-level DEBUG --csv logs\ipvtri_dns_safe.csv
echo.
echo [*] SAFE MODE finished (or crashed). Check logs\ipvtri_dns.log and logs\ipvtri_dns_safe.csv
pause
