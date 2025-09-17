@echo off
cd /d "%~dp0"
set "LOGDIR=logs"
set "OUT=%LOGDIR%\diagnostics.txt"
mkdir "%LOGDIR%" >nul 2>&1

echo ===== IPvTri Diagnostics (%DATE% %TIME%) ===== > "%OUT%"
echo [Python] >> "%OUT%"
python -V >> "%OUT%" 2>&1
python -c "import sys; print(sys.executable)" >> "%OUT%" 2>&1

echo. >> "%OUT%"
echo [Optional Deps] >> "%OUT%"
python - <<PY  >> "%OUT%" 2>&1
import importlib.util
mods=['pystray','PIL','cryptography']
print({m: bool(importlib.util.find_spec(m)) for m in mods})
PY

echo. >> "%OUT%"
echo [PowerShell check] >> "%OUT%"
where powershell >> "%OUT%" 2>&1

echo. >> "%OUT%"
echo [Net adapters] >> "%OUT%"
powershell -NoProfile -Command "(Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object Name, Status, ifIndex) | Format-Table -AutoSize" >> "%OUT%" 2>&1

echo. >> "%OUT%"
echo [Current DNS dump] >> "%OUT%"
netsh interface ipv4 show dnsservers >> "%OUT%" 2>&1

echo. >> "%OUT%"
echo [Test run output] >> "%OUT%"
python ipvtri_dns_super_changer_PRO.py --log-level DEBUG --csv logs\ipvtri_dns_diag.csv >> "%OUT%" 2>&1

echo. >> "%OUT%"
echo ===== End Diagnostics ===== >> "%OUT%"
notepad "%OUT%"
