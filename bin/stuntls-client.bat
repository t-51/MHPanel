@echo off
chcp 65001 >nul
title MHPanel StunTLS Tunnel Client v2.0
color 0b

echo =====================================================================
echo           MHPanel StunTLS WebRTC STUN Tunnel Client v2.0
echo =====================================================================
echo.

:: 1. Check if native standalone stuntls-client.exe exists
if exist "%~dp0stuntls-client.exe" (
    "%~dp0stuntls-client.exe" %*
    goto :end
)

:: 2. Check if python is available for stuntls-client.py
where python >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    if exist "%~dp0stuntls-client.py" (
        set SERVER=%1
        if "%SERVER%"=="" (
            set /p SERVER="Enter StunTLS Server [IP:3478]: "
        )
        set LOCAL_PORT=%2
        if "%LOCAL_PORT%"=="" (
            set LOCAL_PORT=1080
        )
        python "%~dp0stuntls-client.py" -server %SERVER% -l %LOCAL_PORT%
        goto :end
    )
)

:: 3. Neither exe nor python found
echo [!] stuntls-client.exe not found in this folder.
echo [!] Attempting to download stuntls-client.exe...
where curl >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    curl -k -o "%~dp0stuntls-client.exe" "https://13.140.86.132:9090/download/stuntls-client.exe"
    if exist "%~dp0stuntls-client.exe" (
        echo [+] Downloaded successfully! Starting client...
        "%~dp0stuntls-client.exe" %*
        goto :end
    )
)

echo [ERROR] Please download stuntls-client.exe directly from your MHPanel dashboard.
pause

:end
