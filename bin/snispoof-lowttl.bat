@echo off
title MHPanel SNI Spoofing - Low-TTL Decoy Injection
color 0b
echo ======================================================================
echo    MHPanel SNI Spoofing Client: Low-TTL Decoy Injection
echo    Mode: low_ttl
echo ======================================================================
echo.

set SERVER_IP=212.227.143.16
set SERVER_PORT=15443
set RELAY_PORTS=20443,20444,20445,20446,20447,20448,20449,20450,20451,20452,20453,20454,20455,20456,20457,20458,20459,20460,20461,20462,20463,20464,40443
set LOCAL_SOCKS=10808
set LOCAL_RELAY=40443
set FAKE_SNI=sanjesh.org

if exist "%~dp0snispoof-lowttl.exe" (
    "%~dp0snispoof-lowttl.exe" -server %SERVER_IP% -port %SERVER_PORT% -socks %LOCAL_SOCKS% -relay %LOCAL_RELAY% -ports %RELAY_PORTS% -sni %FAKE_SNI% -strategy low_ttl
) else if exist "%~dp0snispoof-client.exe" (
    "%~dp0snispoof-client.exe" -server %SERVER_IP% -port %SERVER_PORT% -socks %LOCAL_SOCKS% -relay %LOCAL_RELAY% -ports %RELAY_PORTS% -sni %FAKE_SNI% -strategy low_ttl
) else (
    python "%~dp0snispoof-lowttl.py" -s %SERVER_IP% -p %SERVER_PORT% -l %LOCAL_SOCKS% --strategy low_ttl
)
pause
