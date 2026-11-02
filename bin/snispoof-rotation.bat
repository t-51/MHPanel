@echo off
title MHPanel SNI Spoofing - Dynamic Decoy SNI Pool Rotation
color 0b
echo ======================================================================
echo    MHPanel SNI Spoofing Client: Dynamic Decoy SNI Pool Rotation
echo    Mode: sni_rotation
echo ======================================================================
echo.

set SERVER_IP=SERVER_IP
set SERVER_PORT=15443
set LOCAL_SOCKS=10808
set LOCAL_RELAY=40443
set FAKE_SNI=auth.vercel.com

if exist "%~dp0snispoof-rotation.exe" (
    "%~dp0snispoof-rotation.exe" -server %SERVER_IP% -port %SERVER_PORT% -socks %LOCAL_SOCKS% -relay %LOCAL_RELAY% -sni %FAKE_SNI% -strategy sni_rotation
) else if exist "%~dp0snispoof-client.exe" (
    "%~dp0snispoof-client.exe" -server %SERVER_IP% -port %SERVER_PORT% -socks %LOCAL_SOCKS% -relay %LOCAL_RELAY% -sni %FAKE_SNI% -strategy sni_rotation
) else (
    python "%~dp0snispoof-rotation.py" -s %SERVER_IP% -p %SERVER_PORT% -l %LOCAL_SOCKS% --strategy sni_rotation
)
pause
