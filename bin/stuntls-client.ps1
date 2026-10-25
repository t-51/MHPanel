<#
.SYNOPSIS
    MHPanel StunTLS Tunnel Client for Windows PowerShell (Zero Dependencies)
    Disguises TCP traffic as RFC 5389 WebRTC STUN packets.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\stuntls-client.ps1 -Server 13.140.86.132:3478 -LocalPort 1080
#>
param(
    [string]$Server = "13.140.86.132:3478",
    [int]$LocalPort = 1080,
    [string]$Key = "stuntls-secret"
)

$Host.UI.RawUI.WindowTitle = "MHPanel StunTLS Tunnel Client v2.0"

$ServerHost = $Server
$ServerPort = 3478
if ($Server -match ":") {
    $parts = $Server -split ":"
    $ServerHost = $parts[0]
    $ServerPort = [int]$parts[1]
}

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "      MHPanel StunTLS Tunnel Client for Windows (RFC 5389)       " -ForegroundColor Yellow
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  [+] Remote StunTLS Server : $ServerHost:$ServerPort" -ForegroundColor White
Write-Host "  [+] Tunnel Mode           : RFC 5389 WebRTC STUN Obfuscation" -ForegroundColor White
Write-Host "  [+] Local Listen Port     : 127.0.0.1:$LocalPort" -ForegroundColor White
Write-Host "  [+] Status                : Active & Ready! Listening for connections..." -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  >>> Set SOCKS5 / TCP in Telegram, Proxifier or Browser: 127.0.0.1:$LocalPort" -ForegroundColor Gray
Write-Host "  >>> Press Ctrl+C to terminate." -ForegroundColor Gray
Write-Host "=================================================================" -ForegroundColor Cyan

$STUN_MAGIC_COOKIE = [byte[]](0x21, 0x12, 0xA4, 0x42)

function Wrap-Stun([byte[]]$Data) {
    $len = $Data.Length
    $hdr = New-Object byte[] 20
    $hdr[0] = 0x00
    $hdr[1] = 0x01 # Binding Request
    $hdr[2] = [byte](($len -shr 8) -band 0xFF)
    $hdr[3] = [byte]($len -band 0xFF)
    $hdr[4] = 0x21
    $hdr[5] = 0x12
    $hdr[6] = 0xA4
    $hdr[7] = 0x42
    
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $transId = New-Object byte[] 12
    $rng.GetBytes($transId)
    [System.Buffer]::BlockCopy($transId, 0, $hdr, 8, 12)
    
    $result = New-Object byte[] (20 + $len)
    [System.Buffer]::BlockCopy($hdr, 0, $result, 0, 20)
    [System.Buffer]::BlockCopy($Data, 0, $result, 20, $len)
    return $result
}

$listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $LocalPort)
$listener.Start()

try {
    while ($true) {
        $client = $listener.AcceptTcpClient()
        [System.Threading.ThreadPool]::QueueUserWorkItem({
            param($cl)
            try {
                $rem = New-Object System.Net.Sockets.TcpClient
                $rem.Connect($using:ServerHost, $using:ServerPort)
                
                $clStream = $cl.GetStream()
                $remStream = $rem.GetStream()
                
                # Forward client -> remote (wrap in STUN)
                [System.Threading.ThreadPool]::QueueUserWorkItem({
                    $buf = New-Object byte[] 16384
                    try {
                        while (($bytesRead = $clStream.Read($buf, 0, $buf.Length)) -gt 0) {
                            $sub = New-Object byte[] $bytesRead
                            [System.Buffer]::BlockCopy($buf, 0, $sub, 0, $bytesRead)
                            $wrapped = Wrap-Stun $sub
                            $remStream.Write($wrapped, 0, $wrapped.Length)
                        }
                    } catch {}
                    finally { try { $rem.Close() } catch {} }
                }) | Out-Null
                
                # Forward remote -> client (unwrap STUN)
                $rBuf = New-Object byte[] 16384
                try {
                    while (($rBytes = $remStream.Read($rBuf, 0, $rBuf.Length)) -gt 0) {
                        # If STUN header is present, unwrap payload
                        if ($rBytes -ge 20 -and $rBuf[4] -eq 0x21 -and $rBuf[5] -eq 0x12 -and $rBuf[6] -eq 0xA4 -and $rBuf[7] -eq 0x42) {
                            $pLen = (($rBuf[2] -shl 8) -bor $rBuf[3])
                            if ($pLen -gt 0 -and $rBytes -ge (20 + $pLen)) {
                                $clStream.Write($rBuf, 20, $pLen)
                            } else {
                                $clStream.Write($rBuf, 20, ($rBytes - 20))
                            }
                        } else {
                            $clStream.Write($rBuf, 0, $rBytes)
                        }
                    }
                } catch {}
                finally { try { $cl.Close() } catch {} }
            } catch {}
        }, $client) | Out-Null
    }
}
finally {
    $listener.Stop()
}
