@echo off
setlocal EnableExtensions EnableDelayedExpansion
set "INSTALL_DIR=%USERPROFILE%\IPvTriDNS\PRO"
set "DESKTOP_LNK=%USERPROFILE%\Desktop\IPvTri DNS PRO.lnk"
set "STARTMENU_DIR=%APPDATA%\Microsoft\Windows\Start Menu\Programs\IPvTriDNS"
set "STARTMENU_LNK=%STARTMENU_DIR%\IPvTri DNS PRO.lnk"

if exist "%INSTALL_DIR%\logs" (
  choice /M "Backup logs to Desktop before uninstall?"
  if errorlevel 1 (
    set "BACKUP_DIR=%USERPROFILE%\Desktop\IPvTriDNS_PRO_Logs_Backup_%RANDOM%"
    mkdir "%BACKUP_DIR%" >nul 2>&1
    xcopy "%INSTALL_DIR%\logs" "%BACKUP_DIR%\logs" /E /I /H /Y >nul 2>&1
  )
)

taskkill /IM python.exe /F >nul 2>&1
taskkill /IM powershell.exe /F >nul 2>&1
taskkill /IM pwsh.exe /F >nul 2>&1

if exist "%STARTMENU_LNK%" del /F /Q "%STARTMENU_LNK%" >nul 2>&1
if exist "%STARTMENU_DIR%" rmdir /S /Q "%STARTMENU_DIR%" >nul 2>&1
if exist "%DESKTOP_LNK%" del /F /Q "%DESKTOP_LNK%" >nul 2>&1
if exist "%INSTALL_DIR%" rmdir /S /Q "%INSTALL_DIR%" >nul 2>&1
echo [✔] Uninstalled.
pause
