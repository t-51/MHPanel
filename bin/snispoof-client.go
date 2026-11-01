// MHPanel SNI Spoofing Client in Go
// Cross-platform, zero dependencies. Compile with: go build -ldflags="-s -w" -o snispoof-client snispoof-client.go

package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

var (
	serverAddr = flag.String("server", "127.0.0.1:15443", "Remote MHPanel SNI Spoof Server (IP:Port)")
	localAddr  = flag.String("local", "127.0.0.1:10808", "Local SOCKS5 listen address")
	strategy   = flag.String("strategy", "tls_fragment", "Strategy: wrong_seq, low_ttl, tls_fragment, sni_rotation")
	decoySNI   = flag.String("sni", "dl.google.com", "Whitelisted decoy SNI domain")
	fragDelay  = flag.Int("delay", 3, "Fragmentation delay in milliseconds")
)

func buildFakeClientHello(sni string) []byte {
	sniBytes := []byte(sni)
	serverName := append([]byte{0x00, byte(len(sniBytes) >> 8), byte(len(sniBytes))}, sniBytes...)
	sniExt := append([]byte{0x00, 0x00, byte((len(serverName) + 2) >> 8), byte(len(serverName) + 2), byte(len(serverName) >> 8), byte(len(serverName))}, serverName...)

	randomBytes := make([]byte, 32)
	rand.Read(randomBytes)
	sessionID := make([]byte, 32)
	rand.Read(sessionID)

	handshakeBody := []byte{0x03, 0x03}
	handshakeBody = append(handshakeBody, randomBytes...)
	handshakeBody = append(handshakeBody, byte(len(sessionID)))
	handshakeBody = append(handshakeBody, sessionID...)
	handshakeBody = append(handshakeBody, []byte{0x00, 0x02, 0x13, 0x01, 0x01, 0x00}...) // ciphers + comp
	extBlock := append([]byte{byte(len(sniExt) >> 8), byte(len(sniExt))}, sniExt...)
	handshakeBody = append(handshakeBody, extBlock...)

	handshakeLen := len(handshakeBody)
	handshake := append([]byte{0x01, byte(handshakeLen >> 16), byte(handshakeLen >> 8), byte(handshakeLen)}, handshakeBody...)
	recordLen := len(handshake)
	record := append([]byte{0x16, 0x03, 0x01, byte(recordLen >> 8), byte(recordLen)}, handshake...)
	return record
}

func handleConnection(client net.Conn) {
	defer client.Close()

	// SOCKS5 Handshake
	buf := make([]byte, 262)
	if _, err := io.ReadFull(client, buf[:2]); err != nil {
		return
	}
	methods := int(buf[1])
	io.ReadFull(client, buf[:methods])
	client.Write([]byte{0x05, 0x00}) // No auth

	// Read SOCKS5 CONNECT request
	req := make([]byte, 4)
	if _, err := io.ReadFull(client, req); err != nil || req[1] != 1 {
		return
	}
	switch req[3] {
	case 1: // IPv4
		io.CopyN(io.Discard, client, 4)
	case 3: // Domain
		var dlen [1]byte
		client.Read(dlen[:])
		io.CopyN(io.Discard, client, int64(dlen[0]))
	case 4: // IPv6
		io.CopyN(io.Discard, client, 16)
	}
	io.CopyN(io.Discard, client, 2) // Port

	// Connect to remote server
	remote, err := net.DialTimeout("tcp", *serverAddr, 8*time.Second)
	if err != nil {
		log.Printf("Failed to connect to remote: %v", err)
		return
	}
	defer remote.Close()

	if *strategy == "low_ttl" || *strategy == "wrong_seq" {
		fake := buildFakeClientHello(*decoySNI)
		remote.Write(fake)
		time.Sleep(time.Duration(*fragDelay) * time.Millisecond)
	}

	// Tell SOCKS5 client success
	client.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x10, 0x80})

	done := make(chan struct{}, 2)
	go func() {
		io.Copy(remote, client)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(client, remote)
		done <- struct{}{}
	}()
	<-done
}

func main() {
	flag.Parse()
	listener, err := net.Listen("tcp", *localAddr)
	if err != nil {
		log.Fatalf("Listen error: %v", err)
	}
	defer listener.Close()

	fmt.Println("==================================================")
	fmt.Printf("MHPanel SNI Spoofing Go Client\n")
	fmt.Printf("Server:   %s\n", *serverAddr)
	fmt.Printf("Local:    %s (SOCKS5)\n", *localAddr)
	fmt.Printf("Strategy: %s\n", *strategy)
	fmt.Println("==================================================")

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleConnection(conn)
	}
}
