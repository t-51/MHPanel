@echo off
title MHPanel SNI Spoofing - Patterniha Pre-ACK Desync
color 0b
echo ======================================================================
echo    MHPanel SNI Spoofing Client: Patterniha Pre-ACK Desync
echo    Mode: patterniha_desync
echo ======================================================================
echo.

set SERVER_IP=SERVER_IP
set SERVER_PORT=15443
set LOCAL_SOCKS=10808
set LOCAL_RELAY=40443
set FAKE_SNI=auth.vercel.com

if exist "%~dp0snispoof-patterniha.exe" (
    "%~dp0snispoof-patterniha.exe" -server %SERVER_IP% -port %SERVER_PORT% -socks %LOCAL_SOCKS% -relay %LOCAL_RELAY% -sni %FAKE_SNI% -strategy patterniha_desync
) else if exist "%~dp0snispoof-client.exe" (
    "%~dp0snispoof-client.exe" -server %SERVER_IP% -port %SERVER_PORT% -socks %LOCAL_SOCKS% -relay %LOCAL_RELAY% -sni %FAKE_SNI% -strategy patterniha_desync
) else (
    python "%~dp0snispoof-patterniha.py" -s %SERVER_IP% -p %SERVER_PORT% -l %LOCAL_SOCKS% --strategy patterniha_desync
)
pause
