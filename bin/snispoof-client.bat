@echo off
title MHPanel SNI Spoofing Client
color 0b
echo ==============================================================
echo        MHPanel SNI Spoofing Anti-DPI Client Loader
echo ==============================================================
echo.

set SERVER_IP=212.227.143.16
set SERVER_PORT=15443
set RELAY_PORTS=20443,20444,20445,20446,20447,20448,20449,20450,20451,20452,20453,20454,20455,20456,20457,20458,20459,20460,20461,20462,20463,20464,40443
set LOCAL_PORT=10808
set STRATEGY=tls_fragment

where python >nul 2>nul
if %ERRORLEVEL% equ 0 (
    python snispoof-client.py -s %SERVER_IP% -p %SERVER_PORT% -l %LOCAL_PORT% --strategy %STRATEGY%
) else (
    powershell -ExecutionPolicy Bypass -File "%~dp0snispoof-client.ps1" -Server %SERVER_IP% -Port %SERVER_PORT% -LocalPort %LOCAL_PORT%
)

pause
