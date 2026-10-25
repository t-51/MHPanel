package main

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
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

	remote, err := net.DialTimeout("tcp", remoteServer, 10*time.Second)
	if err != nil {
		fmt.Printf("[!] Error connecting to server %s: %v\n", remoteServer, err)
		return
	}
	defer remote.Close()

	errc := make(chan error, 2)

	// Local -> Remote (wrap into STUN Binding Request)
	go func() {
		buf := make([]byte, 32768)
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

	// Remote -> Local (unwrap STUN with streaming deframer)
	go func() {
		buf := make([]byte, 32768)
		var streamBuf []byte
		for {
			n, err := remote.Read(buf)
			if n > 0 {
				streamBuf = append(streamBuf, buf[:n]...)
				for len(streamBuf) >= 20 {
					cookie := binary.BigEndian.Uint32(streamBuf[4:8])
					if cookie == StunMagicCookie {
						pLen := int(binary.BigEndian.Uint16(streamBuf[2:4]))
						total := 20 + pLen
						if len(streamBuf) >= total {
							if pLen > 0 {
								local.Write(streamBuf[20:total])
							}
							streamBuf = streamBuf[total:]
						} else {
							break // Need more bytes to complete this STUN frame
						}
					} else {
						// Not a STUN header or raw pass-through, flush buffer
						local.Write(streamBuf)
						streamBuf = streamBuf[:0]
						break
					}
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
	serverFlag := flag.String("server", "", "Remote StunTLS server host:port")
	keyFlag := flag.String("key", "stuntls-secret", "Secret key")
	localFlag := flag.Int("l", 1080, "Local listening port")
	bindFlag := flag.String("b", "127.0.0.1", "Local bind address")

	flag.Parse()

	reader := bufio.NewReader(os.Stdin)
	interactive := (*serverFlag == "")

	serverAddr := strings.TrimSpace(*serverFlag)
	localPort := *localFlag

	if interactive {
		fmt.Println("=================================================================")
		fmt.Println("      MHPanel StunTLS Tunnel Client v2.0 (RFC 5389 Native)       ")
		fmt.Println("=================================================================")
		fmt.Println("  [i] Welcome to StunTLS Client!")
		fmt.Println("  [i] This client obfuscates your VPN/Proxy traffic inside standard")
		fmt.Println("      RFC 5389 WebRTC STUN packets to bypass DPI censorship.")
		fmt.Println("=================================================================")
		fmt.Print("  Enter StunTLS Server [Default: 13.140.86.132:3478]: ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if input == "" {
			serverAddr = "13.140.86.132:3478"
		} else {
			serverAddr = input
		}

		fmt.Print("  Enter Local SOCKS Port [Default: 1080]: ")
		portInput, _ := reader.ReadString('\n')
		portInput = strings.TrimSpace(portInput)
		if portInput != "" {
			if p, err := strconv.Atoi(portInput); err == nil && p > 0 && p < 65536 {
				localPort = p
			}
		}
	}

	if !strings.Contains(serverAddr, ":") {
		serverAddr = serverAddr + ":3478"
	}

	listenAddr := fmt.Sprintf("%s:%d", *bindFlag, localPort)
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		fmt.Println("-----------------------------------------------------------------")
		fmt.Printf("[!] ERROR: Cannot bind to %s: %v\n", listenAddr, err)
		fmt.Printf("[!] Port %d might already be in use by another program.\n", localPort)
		fmt.Println("-----------------------------------------------------------------")
		if interactive {
			fmt.Println("Press Enter to exit...")
			reader.ReadString('\n')
		}
		os.Exit(1)
	}
	defer ln.Close()

	fmt.Println("=================================================================")
	fmt.Println("      MHPanel StunTLS Tunnel Client v2.0 (RFC 5389 Native)       ")
	fmt.Println("=================================================================")
	fmt.Printf("  [+] Remote Server      : %s\n", serverAddr)
	fmt.Printf("  [+] Obfuscation        : RFC 5389 WebRTC STUN Emulation\n")
	fmt.Printf("  [+] Local Listener     : %s\n", listenAddr)
	fmt.Printf("  [+] Secret Key         : %s\n", *keyFlag)
	fmt.Printf("  [+] Status             : [ONLINE & READY]\n")
	fmt.Println("=================================================================")
	fmt.Println("  HOW TO USE:")
	fmt.Printf("  1. In Telegram: Settings -> Proxy -> SOCKS5 -> Host: 127.0.0.1, Port: %d\n", localPort)
	fmt.Printf("  2. In Proxifier / Browser: SOCKS5 127.0.0.1:%d\n", localPort)
	fmt.Println("  >>> DO NOT CLOSE THIS WINDOW WHILE USING THE PROXY.")
	fmt.Println("  >>> Press Ctrl+C to stop.")
	fmt.Println("=================================================================")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("\n[!] StunTLS Client stopped by user.")
		if interactive {
			fmt.Println("Press Enter to close window...")
			reader.ReadString('\n')
		}
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
