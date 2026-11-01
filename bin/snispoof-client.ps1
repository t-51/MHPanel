<#
.SYNOPSIS
MHPanel SNI Spoofing Client Launcher for Windows PowerShell
.DESCRIPTION
Starts local SOCKS5 proxy on 127.0.0.1:10808 connected to MHPanel SNI Spoofing service.
#>
param(
    [string]$Server = "SERVER_IP",
    [int]$Port = 15443,
    [int]$LocalPort = 10808,
    [string]$Strategy = "tls_fragment"
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   MHPanel SNI Spoofing Client (PowerShell Loader)        " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Server: $Server : $Port" -ForegroundColor Yellow
Write-Host "Local SOCKS5: 127.0.0.1:$LocalPort" -ForegroundColor Yellow
Write-Host "Bypass Strategy: $Strategy" -ForegroundColor Yellow
Write-Host ""

$clientScript = Join-Path $PSScriptRoot "snispoof-client.py"
if (-not (Test-Path $clientScript)) {
    Write-Host "[*] Downloading snispoof-client.py from server..." -ForegroundColor White
    try {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
        Invoke-WebRequest -Uri "https://${Server}:${Port}/download/snispoof-client.py" -OutFile $clientScript -UseBasicParsing
    } catch {
        Write-Host "[-] Could not download from HTTPS, trying fallback..." -ForegroundColor Red
    }
}

$pythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $pythonExe) {
    $pythonExe = (Get-Command python3 -ErrorAction SilentlyContinue).Source
}

if ($pythonExe) {
    Write-Host "[+] Launching with Python: $pythonExe" -ForegroundColor Green
    & $pythonExe $clientScript -s $Server -p $Port -l $LocalPort --strategy $Strategy
} else {
    Write-Host "[-] Python not found on this system. Please install Python 3.8+ or use the standalone executable." -ForegroundColor Red
    Pause
}
