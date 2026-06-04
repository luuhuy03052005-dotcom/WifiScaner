@echo off
setlocal EnableExtensions
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator permission...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -WorkingDirectory '%~dp0' -Verb RunAs"
    exit /b
)

where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python was not found in PATH.
    echo Install Python, then run: pip install scapy requests beautifulsoup4 zeroconf
    pause
    exit /b 1
)

echo ========================================================
echo              LAN WATCHER PRO 2026
echo ========================================================
mode con: cols=200 lines=45 >nul 2>&1
echo [*] Dang chay LAN Watcher table dashboard...
echo.
python "%~dp0realtime_lan_watcher_deep.py" --profile aggressive --ui-mode table --offline-after 10

echo.
echo LAN Watcher Pro exited.
pause
