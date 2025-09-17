@echo off
setlocal
set "INSTALL_DIR=%USERPROFILE%\IPvTriDNS\PRO"
if not exist "%INSTALL_DIR%\ipvtri_dns_super_changer_PRO.py" (
  echo [!] Not installed at %INSTALL_DIR%. Run the installer.
  pause
  exit /b 1
)
start "" /D "%INSTALL_DIR%" cmd /k ^
 "echo [*] In %CD% & echo. & py -3 -V & echo. & py -3 -u ipvtri_dns_super_changer_PRO.py --log-level INFO --csv logs\ipvtri_dns.csv --enforce-doh & echo. & echo [*] Done. Type 'exit' to close."
