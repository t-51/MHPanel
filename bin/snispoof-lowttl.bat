@echo off
title MHPanel SNI Spoofing - Low-TTL Decoy Injection
color 0b
echo ======================================================================
echo    MHPanel SNI Spoofing Client: Low-TTL Decoy Injection
echo    Mode: low_ttl
echo ======================================================================
echo.

set SERVER_IP=SERVER_IP
set SERVER_PORT=15443
set LOCAL_SOCKS=10808
set LOCAL_RELAY=40443
set FAKE_SNI=auth.vercel.com

if exist "%~dp0snispoof-lowttl.exe" (
    "%~dp0snispoof-lowttl.exe" -server %SERVER_IP% -port %SERVER_PORT% -socks %LOCAL_SOCKS% -relay %LOCAL_RELAY% -sni %FAKE_SNI% -strategy low_ttl
) else if exist "%~dp0snispoof-client.exe" (
    "%~dp0snispoof-client.exe" -server %SERVER_IP% -port %SERVER_PORT% -socks %LOCAL_SOCKS% -relay %LOCAL_RELAY% -sni %FAKE_SNI% -strategy low_ttl
) else (
    python "%~dp0snispoof-lowttl.py" -s %SERVER_IP% -p %SERVER_PORT% -l %LOCAL_SOCKS% --strategy low_ttl
)
pause
