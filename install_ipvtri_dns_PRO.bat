@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "INSTALL_DIR=%USERPROFILE%\IPvTriDNS\PRO"
set "DESKTOP_LNK=%USERPROFILE%\Desktop\IPvTri DNS PRO.lnk"
set "STARTMENU_DIR=%APPDATA%\Microsoft\Windows\Start Menu\Programs\IPvTriDNS"
set "STARTMENU_LNK=%STARTMENU_DIR%\IPvTri DNS PRO.lnk"

echo [*] Installing to %INSTALL_DIR%
mkdir "%INSTALL_DIR%" >nul 2>&1
mkdir "%STARTMENU_DIR%" >nul 2>&1

for %%F in (
  "ipvtri_dns_super_changer_PRO.py"
  "Run_IPvTri_DNS_PRO.bat"
  "Run_IPvTri_DNS_PRO_SAFE.bat"
  "Run_IPvTri_DNS_PRO_SHELL.bat"
  "diagnose_ipvtri.bat"
  "trusted_dns_list.txt"
  "requirements-optional.txt"
  "install_optional_deps.bat"
  "README.md"
  "INSTRUCTIONS_NO_GOOGLE_GUARDED.md"
) do (
  if exist "%%~F" copy /Y "%%~F" "%INSTALL_DIR%" >nul & echo [+] Copied %%~F
)

mkdir "%INSTALL_DIR%\logs" >nul 2>&1

echo [+] Creating Desktop shortcut (Shell launcher)...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('%DESKTOP_LNK%'); $s.TargetPath='%INSTALL_DIR%\Run_IPvTri_DNS_PRO_SHELL.bat'; $s.WorkingDirectory='%INSTALL_DIR%'; $s.IconLocation='%SystemRoot%\System32\shell32.dll,135'; $s.Save()"

echo [+] Creating Start Menu shortcut (Shell launcher)...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('%STARTMENU_LNK%'); $s.TargetPath='%INSTALL_DIR%\Run_IPvTri_DNS_PRO_SHELL.bat'; $s.WorkingDirectory='%INSTALL_DIR%'; $s.IconLocation='%SystemRoot%\System32\shell32.dll,135'; $s.Save()"

echo.
choice /M "Install optional features now (pystray, Pillow, cryptography)?"
if errorlevel 2 goto SKIP_OPT

pushd "%INSTALL_DIR%"
py -3 -m ensurepip --upgrade >nul 2>&1
py -3 -m pip install --upgrade pip
py -3 -m pip install -r requirements-optional.txt
popd

:SKIP_OPT
echo [✔] Installation complete.
echo [→] Desktop: IPvTri DNS PRO
echo [→] Start Menu: Programs > IPvTriDNS > IPvTri DNS PRO
pause
