@echo off
title MHPanel SNI Spoofing - Out-of-Window TCP Sequence
color 0b
echo ======================================================================
echo    MHPanel SNI Spoofing Client: Out-of-Window TCP Sequence
echo    Mode: wrong_seq
echo ======================================================================
echo.

set SERVER_IP=SERVER_IP
set SERVER_PORT=15443
set LOCAL_SOCKS=10808
set LOCAL_RELAY=40443
set FAKE_SNI=auth.vercel.com

if exist "%~dp0snispoof-wrongseq.exe" (
    "%~dp0snispoof-wrongseq.exe" -server %SERVER_IP% -port %SERVER_PORT% -socks %LOCAL_SOCKS% -relay %LOCAL_RELAY% -sni %FAKE_SNI% -strategy wrong_seq
) else if exist "%~dp0snispoof-client.exe" (
    "%~dp0snispoof-client.exe" -server %SERVER_IP% -port %SERVER_PORT% -socks %LOCAL_SOCKS% -relay %LOCAL_RELAY% -sni %FAKE_SNI% -strategy wrong_seq
) else (
    python "%~dp0snispoof-wrongseq.py" -s %SERVER_IP% -p %SERVER_PORT% -l %LOCAL_SOCKS% --strategy wrong_seq
)
pause
