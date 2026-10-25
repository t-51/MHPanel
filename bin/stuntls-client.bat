@echo off
chcp 65001 >nul
title MHPanel StunTLS Tunnel Client v2.0
color 0b

echo =====================================================================
echo           MHPanel StunTLS WebRTC STUN Tunnel Client v2.0
echo =====================================================================
echo.

where python >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python is not installed or not in your Windows PATH!
    echo Please install Python 3 from https://www.python.org/downloads/
    echo Or run stuntls-client.ps1 using PowerShell.
    echo.
    pause
    exit /b 1
)

set SERVER=%1
if "%SERVER%"=="" (
    set /p SERVER="Enter StunTLS Server [IP:3478]: "
)

set LOCAL_PORT=%2
if "%LOCAL_PORT%"=="" (
    set LOCAL_PORT=1080
)

echo [+] Connecting to StunTLS Server: %SERVER%
echo [+] Local Listening Port: 127.0.0.1:%LOCAL_PORT%
echo.

python "%~dp0stuntls-client.py" -server %SERVER% -l %LOCAL_PORT%

pause
