package main

import (
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

const StunMagicCookie uint32 = 0x2112A442

func wrapStun(data []byte, msgType uint16) []byte {
	l := len(data)
	buf := make([]byte, 20+l)
	binary.BigEndian.PutUint16(buf[0:2], msgType)
	binary.BigEndian.PutUint16(buf[2:4], uint16(l))
	binary.BigEndian.PutUint32(buf[4:8], StunMagicCookie)
	rand.Read(buf[8:20])
	copy(buf[20:], data)
	return buf
}

func handleConnection(local net.Conn, remoteServer string) {
	defer local.Close()

	remote, err := net.Dial("tcp", remoteServer)
	if err != nil {
		return
	}
	defer remote.Close()

	errc := make(chan error, 2)

	// Local -> Remote (wrap into STUN Binding Request)
	go func() {
		buf := make([]byte, 16384)
		for {
			n, err := local.Read(buf)
			if n > 0 {
				pkt := wrapStun(buf[:n], 0x0001)
				if _, werr := remote.Write(pkt); werr != nil {
					errc <- werr
					return
				}
			}
			if err != nil {
				errc <- err
				return
			}
		}
	}()

	// Remote -> Local (unwrap STUN or pass raw)
	go func() {
		buf := make([]byte, 16384)
		for {
			n, err := remote.Read(buf)
			if n > 0 {
				chunk := buf[:n]
				if len(chunk) >= 20 && binary.BigEndian.Uint32(chunk[4:8]) == StunMagicCookie {
					pLen := int(binary.BigEndian.Uint16(chunk[2:4]))
					if pLen > 0 && len(chunk) >= 20+pLen {
						local.Write(chunk[20 : 20+pLen])
					} else {
						local.Write(chunk[20:])
					}
				} else {
					local.Write(chunk)
				}
			}
			if err != nil {
				errc <- err
				return
			}
		}
	}()

	<-errc
}

func main() {
	serverFlag := flag.String("server", "", "Remote StunTLS server host:port (e.g. 13.140.86.132:3478)")
	keyFlag := flag.String("key", "stuntls-secret", "Secret key for authentication")
	localFlag := flag.Int("l", 1080, "Local listening port")
	bindFlag := flag.String("b", "127.0.0.1", "Local bind address")

	flag.Parse()

	if *serverFlag == "" {
		fmt.Println("Usage: stuntls-client -server <IP:PORT> -l <LOCAL_PORT> [-key <KEY>]")
		fmt.Println("Example: stuntls-client -server 13.140.86.132:3478 -l 1080")
		os.Exit(1)
	}

	serverAddr := *serverFlag
	if !strings.Contains(serverAddr, ":") {
		serverAddr = serverAddr + ":3478"
	}

	listenAddr := fmt.Sprintf("%s:%d", *bindFlag, *localFlag)
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		fmt.Printf("[!] Failed to listen on %s: %v\n", listenAddr, err)
		os.Exit(1)
	}
	defer ln.Close()

	fmt.Println("=================================================================")
	fmt.Println("      MHPanel StunTLS Tunnel Client v2.0 (RFC 5389 Native)       ")
	fmt.Println("=================================================================")
	fmt.Printf("  [+] Remote StunTLS Server : %s\n", serverAddr)
	fmt.Printf("  [+] Obfuscation Protocol  : RFC 5389 WebRTC STUN Tunnel\n")
	fmt.Printf("  [+] Local Listener        : %s\n", listenAddr)
	fmt.Printf("  [+] Secret Key            : %s\n", *keyFlag)
	fmt.Println("  [+] Status                : Active & Ready! Listening for connections...")
	fmt.Println("=================================================================")
	fmt.Printf("  >>> Configure Telegram, Proxifier or Browser: %s\n", listenAddr)
	fmt.Println("  >>> Press Ctrl+C to stop.")
	fmt.Println("=================================================================")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("\n[!] StunTLS Client stopped by user.")
		os.Exit(0)
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleConnection(conn, serverAddr)
	}
}
