@echo off
title MHPanel SNI Spoofing Client
color 0b
echo ==============================================================
echo        MHPanel SNI Spoofing Anti-DPI Client Loader
echo ==============================================================
echo.

set SERVER_IP=SERVER_IP
set SERVER_PORT=15443
set LOCAL_PORT=10808
set STRATEGY=tls_fragment

where python >nul 2>nul
if %ERRORLEVEL% equ 0 (
    python snispoof-client.py -s %SERVER_IP% -p %SERVER_PORT% -l %LOCAL_PORT% --strategy %STRATEGY%
) else (
    powershell -ExecutionPolicy Bypass -File "%~dp0snispoof-client.ps1" -Server %SERVER_IP% -Port %SERVER_PORT% -LocalPort %LOCAL_PORT%
)

pause
