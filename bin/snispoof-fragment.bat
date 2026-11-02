@echo off
title MHPanel SNI Spoofing - TLS Fragmentation & SNI Slicing
color 0b
echo ======================================================================
echo    MHPanel SNI Spoofing Client: TLS Fragmentation & SNI Slicing
echo    Mode: tls_fragment
echo ======================================================================
echo.

set SERVER_IP=SERVER_IP
set SERVER_PORT=15443
set LOCAL_SOCKS=10808
set LOCAL_RELAY=40443
set FAKE_SNI=auth.vercel.com

if exist "%~dp0snispoof-fragment.exe" (
    "%~dp0snispoof-fragment.exe" -server %SERVER_IP% -port %SERVER_PORT% -socks %LOCAL_SOCKS% -relay %LOCAL_RELAY% -sni %FAKE_SNI% -strategy tls_fragment
) else if exist "%~dp0snispoof-client.exe" (
    "%~dp0snispoof-client.exe" -server %SERVER_IP% -port %SERVER_PORT% -socks %LOCAL_SOCKS% -relay %LOCAL_RELAY% -sni %FAKE_SNI% -strategy tls_fragment
) else (
    python "%~dp0snispoof-fragment.py" -s %SERVER_IP% -p %SERVER_PORT% -l %LOCAL_SOCKS% --strategy tls_fragment
)
pause
