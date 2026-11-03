// MHPanel & Patterniha SNI-Spoofing Windows Terminal Client
// Cross-platform, standalone binary with Interactive Open/Close & Anti-DPI Multi-Port Evasion Engine
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type Config struct {
	ServerDomain    string `json:"server_domain"`
	ServerIP        string `json:"server_ip"`
	ServerPort      int    `json:"server_port"`
	LocalSocksPort  int    `json:"local_socks_port"`
	LocalRelayPort  int    `json:"local_relay_port"`
	RelayPorts      []int  `json:"relay_ports"`
	FakeSNI         string `json:"fake_sni"`
	Strategy        string `json:"strategy"` // patterniha_desync, tls_fragment, wrong_seq, low_ttl, wrong_checksum, direct
	LowTTLHops      int    `json:"low_ttl_hops"`
	FragmentSize    int    `json:"fragment_size"`
	FragmentDelayMs int    `json:"fragment_delay_ms"`
	AutoStart       bool   `json:"auto_start"`
}

var defaultConfig = Config{
	ServerDomain:    "",
	ServerIP:        "127.0.0.1",
	ServerPort:      15443,
	LocalSocksPort:  10808,
	LocalRelayPort:  40443,
	RelayPorts:      []int{20443, 20452, 20453, 20451, 20454, 20455, 20456, 20448, 20457, 20458, 20459, 20444, 20460, 20461, 20462, 40443},
	FakeSNI:         "auth.vercel.com",
	Strategy:        "patterniha_desync",
	LowTTLHops:      5,
	FragmentSize:    2,
	FragmentDelayMs: 3,
	AutoStart:       true,
}

var popularSNIs = []struct {
	Domain string
	Label  string
}{
	{"auth.vercel.com", "Vercel Global Edge (Default)"},
	{"dl.google.com", "Google Services & Chrome CDN"},
	{"speedtest.net", "Ookla Speedtest CDN"},
	{"sanjesh.org", "National Educational Portal"},
	{"shaparak.ir", "Banking & Payment Gateway"},
	{"cloudflare.com", "Cloudflare Global Edge"},
	{"microsoft.com", "Microsoft Azure Cloud"},
	{"telewebion.com", "Broadcasting Media CDN"},
	{"divar.ir", "Local CDN Whitelist"},
}

var (
	cfg                 Config
	cfgMutex            sync.RWMutex
	cfgPath             string
	running             int32
	socksListener       net.Listener
	relayListener       net.Listener
	extraListeners      []net.Listener
	extraListenersMutex sync.Mutex
	activeConns         int64
	bytesTx             int64
	bytesRx             int64
	connsMutex          sync.Mutex
	openSockets         = make(map[net.Conn]struct{})
)

func getExeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

func getSnapshotConfig() Config {
	cfgMutex.RLock()
	defer cfgMutex.RUnlock()
	return cfg
}

func loadConfig() {
	exeName := strings.ToLower(filepath.Base(os.Args[0]))
	if strings.Contains(exeName, "patterniha") {
		defaultConfig.Strategy = "patterniha_desync"
	} else if strings.Contains(exeName, "fragment") {
		defaultConfig.Strategy = "tls_fragment"
	} else if strings.Contains(exeName, "lowttl") || strings.Contains(exeName, "ttl") {
		defaultConfig.Strategy = "low_ttl"
	} else if strings.Contains(exeName, "wrongseq") || strings.Contains(exeName, "wrong_seq") {
		defaultConfig.Strategy = "wrong_seq"
	} else if strings.Contains(exeName, "checksum") {
		defaultConfig.Strategy = "wrong_checksum"
	} else if strings.Contains(exeName, "rotation") {
		defaultConfig.Strategy = "sni_rotation"
	}

	cfgPath = filepath.Join(getExeDir(), "config.json")
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		cfg = defaultConfig
		saveConfig()
		return
	}

	var rawMap map[string]interface{}
	if err := json.Unmarshal(data, &rawMap); err == nil {
		cfg = defaultConfig
		if val, ok := rawMap["server_domain"].(string); ok {
			cfg.ServerDomain = val
		}
		if val, ok := rawMap["CONNECT_IP"].(string); ok {
			cfg.ServerIP = val
		}
		if val, ok := rawMap["CONNECT_PORT"].(float64); ok {
			cfg.ServerPort = int(val)
		}
		if val, ok := rawMap["LISTEN_PORT"].(float64); ok {
			cfg.LocalRelayPort = int(val)
		}
		if val, ok := rawMap["FAKE_SNI"].(string); ok {
			cfg.FakeSNI = val
		}

		// Support standard fields
		if val, ok := rawMap["server_ip"].(string); ok {
			cfg.ServerIP = val
		}
		if val, ok := rawMap["server_port"].(float64); ok {
			cfg.ServerPort = int(val)
		}
		if val, ok := rawMap["local_socks_port"].(float64); ok {
			cfg.LocalSocksPort = int(val)
		}
		if val, ok := rawMap["local_relay_port"].(float64); ok {
			cfg.LocalRelayPort = int(val)
		}
		if portsArr, ok := rawMap["relay_ports"].([]interface{}); ok {
			var pList []int
			for _, item := range portsArr {
				if pf, ok := item.(float64); ok && pf > 0 {
					pList = append(pList, int(pf))
				}
			}
			if len(pList) > 0 {
				cfg.RelayPorts = pList
			}
		}
		if val, ok := rawMap["fake_sni"].(string); ok {
			cfg.FakeSNI = val
		}
		if val, ok := rawMap["strategy"].(string); ok {
			cfg.Strategy = val
		}
		if val, ok := rawMap["low_ttl_hops"].(float64); ok {
			cfg.LowTTLHops = int(val)
		}
		if val, ok := rawMap["fragment_size"].(float64); ok {
			cfg.FragmentSize = int(val)
		}
		if val, ok := rawMap["fragment_delay_ms"].(float64); ok {
			cfg.FragmentDelayMs = int(val)
		}
		if val, ok := rawMap["auto_start"].(bool); ok {
			cfg.AutoStart = val
		}
	} else {
		cfg = defaultConfig
	}
}

func saveConfig() {
	cfgMutex.RLock()
	data, err := json.MarshalIndent(cfg, "", "  ")
	cfgMutex.RUnlock()
	if err == nil {
		_ = os.WriteFile(cfgPath, data, 0644)
	}
}

func buildFakeClientHello(sni string) []byte {
	sniBytes := []byte(sni)
	serverName := append([]byte{0x00, byte(len(sniBytes) >> 8), byte(len(sniBytes))}, sniBytes...)
	sniExt := append([]byte{0x00, 0x00, byte((len(serverName) + 2) >> 8), byte(len(serverName) + 2), byte(len(serverName) >> 8), byte(len(serverName))}, serverName...)

	randomBytes := make([]byte, 32)
	_, _ = rand.Read(randomBytes)
	sessionID := make([]byte, 32)
	_, _ = rand.Read(sessionID)

	handshakeBody := []byte{0x03, 0x03}
	handshakeBody = append(handshakeBody, randomBytes...)
	handshakeBody = append(handshakeBody, byte(len(sessionID)))
	handshakeBody = append(handshakeBody, sessionID...)
	handshakeBody = append(handshakeBody, []byte{0x00, 0x02, 0x13, 0x01, 0x01, 0x00}...)
	extBlock := append([]byte{byte(len(sniExt) >> 8), byte(len(sniExt))}, sniExt...)
	handshakeBody = append(handshakeBody, extBlock...)

	handshakeLen := len(handshakeBody)
	handshake := append([]byte{0x01, byte(handshakeLen >> 16), byte(handshakeLen >> 8), byte(handshakeLen)}, handshakeBody...)
	recordLen := len(handshake)
	record := append([]byte{0x16, 0x03, 0x01, byte(recordLen >> 8), byte(recordLen)}, handshake...)
	return record
}

func findSNIOffset(data []byte) (start, end int, host string) {
	if len(data) < 5 || data[0] != 0x16 {
		return -1, -1, ""
	}
	recordLen := int(data[3])<<8 | int(data[4])
	if len(data) < 5+recordLen || data[5] != 0x01 {
		return -1, -1, ""
	}
	pos := 43
	if pos >= len(data) {
		return -1, -1, ""
	}
	sessIDLen := int(data[pos])
	pos += 1 + sessIDLen
	if pos+2 > len(data) {
		return -1, -1, ""
	}
	cipherLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2 + cipherLen
	if pos+1 > len(data) {
		return -1, -1, ""
	}
	compLen := int(data[pos])
	pos += 1 + compLen
	if pos+2 > len(data) {
		return -1, -1, ""
	}
	extTotalLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2
	extEnd := pos + extTotalLen

	for pos+4 <= extEnd && pos+4 <= len(data) {
		extType := int(data[pos])<<8 | int(data[pos+1])
		extLen := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4
		if extType == 0 { // SNI
			if pos+2 <= len(data) {
				if pos+2 < len(data) && data[pos+2] == 0 && pos+5 <= len(data) {
					nameLen := int(data[pos+3])<<8 | int(data[pos+4])
					hStart := pos + 5
					hEnd := hStart + nameLen
					if hEnd <= len(data) {
						return hStart, hEnd, string(data[hStart:hEnd])
					}
				}
			}
		}
		pos += extLen
	}
	return -1, -1, ""
}

func registerConn(c net.Conn) {
	connsMutex.Lock()
	openSockets[c] = struct{}{}
	connsMutex.Unlock()
	atomic.AddInt64(&activeConns, 1)
}

func unregisterConn(c net.Conn) {
	connsMutex.Lock()
	delete(openSockets, c)
	connsMutex.Unlock()
	atomic.AddInt64(&activeConns, -1)
	_ = c.Close()
}

func closeAllConns() {
	connsMutex.Lock()
	for c := range openSockets {
		_ = c.Close()
		delete(openSockets, c)
	}
	connsMutex.Unlock()
	atomic.StoreInt64(&activeConns, 0)
}

func connectRemote(targetAddr string, currentCfg Config, targetPort int) (net.Conn, error) {
	d := net.Dialer{Timeout: 8 * time.Second}
	remote, err := d.Dial("tcp", targetAddr)
	if err != nil {
		return nil, err
	}

	if tcpConn, ok := remote.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(15 * time.Second)
	}

	// Send target port routing header (MAGIC: SNIP + 2 bytes targetPort uint16)
	if targetPort > 0 {
		routingHead := []byte{0x53, 0x4e, 0x49, 0x50, byte(targetPort >> 8), byte(targetPort & 0xff)}
		_, _ = remote.Write(routingHead)
	}

	switch currentCfg.Strategy {
	case "patterniha_desync", "wrong_seq", "fake_sni":
		fakeHello := buildFakeClientHello(currentCfg.FakeSNI)
		_, _ = remote.Write(fakeHello)
		delay := time.Duration(currentCfg.FragmentDelayMs) * time.Millisecond
		if delay <= 0 {
			delay = 3 * time.Millisecond
		}
		time.Sleep(delay)
	case "low_ttl":
		fakeHello := buildFakeClientHello(currentCfg.FakeSNI)
		_, _ = remote.Write(fakeHello)
		time.Sleep(time.Duration(currentCfg.FragmentDelayMs) * time.Millisecond)
	}

	return remote, nil
}

func relayData(src, dst net.Conn, applyFrag bool, currentCfg Config, isClientToRemote bool) {
	buf := make([]byte, 32768)
	firstPacket := true

	for {
		nr, err := src.Read(buf)
		if nr > 0 {
			data := buf[:nr]
			if isClientToRemote {
				atomic.AddInt64(&bytesTx, int64(nr))
			} else {
				atomic.AddInt64(&bytesRx, int64(nr))
			}

			if firstPacket && isClientToRemote && applyFrag && (currentCfg.Strategy == "tls_fragment" || currentCfg.Strategy == "patterniha_desync") {
				firstPacket = false
				start, _, _ := findSNIOffset(data)
				fragSize := currentCfg.FragmentSize
				if fragSize <= 0 {
					fragSize = 2
				}
				delay := time.Duration(currentCfg.FragmentDelayMs) * time.Millisecond

				if start > 0 && start+fragSize < len(data) {
					_, _ = dst.Write(data[:start+fragSize])
					time.Sleep(delay)
					_, _ = dst.Write(data[start+fragSize:])
					continue
				} else if len(data) > 10 {
					split := len(data) / 2
					if split > 20 {
						split = 20
					}
					_, _ = dst.Write(data[:split])
					time.Sleep(delay)
					_, _ = dst.Write(data[split:])
					continue
				}
			}

			firstPacket = false
			nw, ew := dst.Write(data)
			if ew != nil || nw != nr {
				break
			}
		}
		if err != nil {
			break
		}
	}
}

func handleTCPRelay(client net.Conn, targetAddr string, targetPort int) {
	registerConn(client)
	defer unregisterConn(client)

	currentCfg := getSnapshotConfig()
	remote, err := connectRemote(targetAddr, currentCfg, targetPort)
	if err != nil {
		return
	}
	registerConn(remote)
	defer unregisterConn(remote)

	done := make(chan struct{}, 2)
	go func() {
		relayData(client, remote, true, currentCfg, true)
		done <- struct{}{}
	}()
	go func() {
		relayData(remote, client, false, currentCfg, false)
		done <- struct{}{}
	}()
	<-done
}

func handleSocks5(client net.Conn, targetAddr string) {
	registerConn(client)
	defer unregisterConn(client)

	head := make([]byte, 2)
	if _, err := io.ReadFull(client, head); err != nil || head[0] != 0x05 {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}
	_, _ = client.Write([]byte{0x05, 0x00})

	req := make([]byte, 4)
	if _, err := io.ReadFull(client, req); err != nil || req[1] != 0x01 {
		return
	}

	switch req[3] {
	case 1:
		buf := make([]byte, 4)
		_, _ = io.ReadFull(client, buf)
	case 3:
		var l [1]byte
		_, _ = io.ReadFull(client, l[:])
		domainBuf := make([]byte, int(l[0]))
		_, _ = io.ReadFull(client, domainBuf)
	case 4:
		buf := make([]byte, 16)
		_, _ = io.ReadFull(client, buf)
	}
	portBuf := make([]byte, 2)
	_, _ = io.ReadFull(client, portBuf)
	targetPort := int(portBuf[0])<<8 | int(portBuf[1])
	if targetPort <= 0 {
		targetPort = 20443
	}

	currentCfg := getSnapshotConfig()
	remote, err := connectRemote(targetAddr, currentCfg, targetPort)
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	registerConn(remote)
	defer unregisterConn(remote)

	_, _ = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x10, 0x80})

	done := make(chan struct{}, 2)
	go func() {
		relayData(client, remote, true, currentCfg, true)
		done <- struct{}{}
	}()
	go func() {
		relayData(remote, client, false, currentCfg, false)
		done <- struct{}{}
	}()
	<-done
}

func StartProxy() error {
	if atomic.LoadInt32(&running) == 1 {
		return fmt.Errorf("proxy is already running")
	}

	currentCfg := getSnapshotConfig()
	targetHost := currentCfg.ServerIP
	if currentCfg.ServerDomain != "" {
		targetHost = currentCfg.ServerDomain
	}
	targetAddr := fmt.Sprintf("%s:%d", targetHost, currentCfg.ServerPort)

	sAddr := fmt.Sprintf("0.0.0.0:%d", currentCfg.LocalSocksPort)
	sList, err := net.Listen("tcp", sAddr)
	if err != nil {
		return fmt.Errorf("failed to bind SOCKS5 port %d: %v", currentCfg.LocalSocksPort, err)
	}
	socksListener = sList

	rAddr := fmt.Sprintf("0.0.0.0:%d", currentCfg.LocalRelayPort)
	rList, err := net.Listen("tcp", rAddr)
	if err != nil {
		_ = socksListener.Close()
		return fmt.Errorf("failed to bind TCP Relay port %d: %v", currentCfg.LocalRelayPort, err)
	}
	relayListener = rList

	atomic.StoreInt32(&running, 1)

	// SOCKS5 listener
	go func() {
		for atomic.LoadInt32(&running) == 1 {
			c, err := sList.Accept()
			if err != nil {
				break
			}
			go handleSocks5(c, targetAddr)
		}
	}()

	// Universal fallback TCP Relay listener (:40443 -> default target 20443)
	go func() {
		for atomic.LoadInt32(&running) == 1 {
			c, err := rList.Accept()
			if err != nil {
				break
			}
			go handleTCPRelay(c, targetAddr, 20443)
		}
	}()

	// Auto-bind multi-port relay listeners on 127.0.0.1 for every panel inbound port
	extraListenersMutex.Lock()
	extraListeners = nil
	for _, p := range currentCfg.RelayPorts {
		if p <= 0 || p == currentCfg.LocalSocksPort || p == currentCfg.LocalRelayPort {
			continue
		}
		pAddr := fmt.Sprintf("127.0.0.1:%d", p)
		pList, pErr := net.Listen("tcp", pAddr)
		if pErr == nil {
			extraListeners = append(extraListeners, pList)
			targetP := p
			go func(l net.Listener, port int) {
				for atomic.LoadInt32(&running) == 1 {
					c, err := l.Accept()
					if err != nil {
						break
					}
					go handleTCPRelay(c, targetAddr, port)
				}
			}(pList, targetP)
		}
	}
	extraListenersMutex.Unlock()

	return nil
}

func StopProxy() {
	if atomic.CompareAndSwapInt32(&running, 1, 0) {
		if socksListener != nil {
			_ = socksListener.Close()
		}
		if relayListener != nil {
			_ = relayListener.Close()
		}
		extraListenersMutex.Lock()
		for _, l := range extraListeners {
			_ = l.Close()
		}
		extraListeners = nil
		extraListenersMutex.Unlock()
		closeAllConns()
	}
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func clearScreen() {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		_ = cmd.Run()
	} else {
		cmd := exec.Command("clear")
		cmd.Stdout = os.Stdout
		_ = cmd.Run()
	}
}

func printBanner() {
	clearScreen()
	fmt.Println("======================================================================")
	fmt.Println("   MHPanel & Patterniha SNI-Spoofing Windows Terminal Client (v2.0)   ")
	fmt.Println("======================================================================")

	currentCfg := getSnapshotConfig()

	statusStr := "[STOPPED - Closed]"
	if atomic.LoadInt32(&running) == 1 {
		statusStr = "[RUNNING - Open / Active]"
	}

	targetDisplay := currentCfg.ServerIP
	if currentCfg.ServerDomain != "" {
		targetDisplay = fmt.Sprintf("%s (%s)", currentCfg.ServerDomain, currentCfg.ServerIP)
	}

	fmt.Printf(" Proxy Status:          %s\n", statusStr)
	fmt.Printf(" Target Server:         %s:%d\n", targetDisplay, currentCfg.ServerPort)
	fmt.Printf(" Local SOCKS5 Proxy:    127.0.0.1:%d (Auto-routes ANY Port & Domain)\n", currentCfg.LocalSocksPort)
	fmt.Printf(" Universal Relay Port:  127.0.0.1:%d\n", currentCfg.LocalRelayPort)
	if len(currentCfg.RelayPorts) > 0 {
		var pStrs []string
		for _, p := range currentCfg.RelayPorts {
			if len(pStrs) < 8 {
				pStrs = append(pStrs, strconv.Itoa(p))
			}
		}
		fmt.Printf(" Auto-Bound Ports:      %s... (Active on 127.0.0.1)\n", strings.Join(pStrs, ", "))
	}
	fmt.Printf(" Active Strategy:       %s\n", currentCfg.Strategy)
	fmt.Printf(" Decoy SNI Domain:      %s\n", currentCfg.FakeSNI)
	fmt.Printf(" Active Connections:    %d\n", atomic.LoadInt64(&activeConns))
	fmt.Printf(" Total Traffic:         TX: %s | RX: %s\n", formatBytes(atomic.LoadInt64(&bytesTx)), formatBytes(atomic.LoadInt64(&bytesRx)))
	if currentCfg.ServerIP == "127.0.0.1" && currentCfg.ServerDomain == "" {
		fmt.Println("----------------------------------------------------------------------")
		fmt.Println(" [!] NOTICE: Target Server is set to 127.0.0.1 (Localhost)!")
		fmt.Println("     If running on a client PC, choose [3] to set your VPS Server IP.")
	}
	fmt.Println("----------------------------------------------------------------------")
	fmt.Println(" [1] Start / Open Proxy")
	fmt.Println(" [2] Stop / Close Proxy")
	fmt.Println(" [3] Server Domain, IP & Ports Settings")
	fmt.Println(" [4] Change Decoy SNI Domain")
	fmt.Println(" [5] Change Evasion Strategy")
	fmt.Println(" [6] V2Ray / Sing-box / Xray Setup Guide (Zero-Config Tutorial)")
	fmt.Println(" [7] Refresh Status & Statistics")
	fmt.Println(" [Q/8] Quit / Exit")
	fmt.Println("======================================================================")
	fmt.Print("Please select an option (1-8 or Q): ")
}

func configureServer(reader *bufio.Reader) {
	currentCfg := getSnapshotConfig()

	fmt.Println("\n======================================================================")
	fmt.Println("                  SERVER & PORTS CONFIGURATION                        ")
	fmt.Println("======================================================================")
	curHost := currentCfg.ServerDomain
	if curHost == "" {
		curHost = currentCfg.ServerIP
	}
	fmt.Printf("Enter Target Server Domain or IP [%s]: ", curHost)
	hostInput, _ := reader.ReadString('\n')
	hostInput = strings.TrimSpace(hostInput)
	if hostInput == "" {
		hostInput = curHost
	}

	fmt.Printf("Enter Target Server Port [%d]: ", currentCfg.ServerPort)
	portStr, _ := reader.ReadString('\n')
	portStr = strings.TrimSpace(portStr)
	port := currentCfg.ServerPort
	if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
		port = p
	}

	fmt.Printf("Enter Local SOCKS5 Port [%d]: ", currentCfg.LocalSocksPort)
	socksStr, _ := reader.ReadString('\n')
	socksStr = strings.TrimSpace(socksStr)
	socks := currentCfg.LocalSocksPort
	if s, err := strconv.Atoi(socksStr); err == nil && s > 0 {
		socks = s
	}

	fmt.Printf("Enter Local Universal Relay Port [%d]: ", currentCfg.LocalRelayPort)
	relayStr, _ := reader.ReadString('\n')
	relayStr = strings.TrimSpace(relayStr)
	relay := currentCfg.LocalRelayPort
	if r, err := strconv.Atoi(relayStr); err == nil && r > 0 {
		relay = r
	}

	cfgMutex.Lock()
	if net.ParseIP(hostInput) != nil {
		cfg.ServerIP = hostInput
	} else {
		cfg.ServerDomain = hostInput
		if ips, err := net.LookupIP(hostInput); err == nil && len(ips) > 0 {
			cfg.ServerIP = ips[0].String()
		}
	}
	cfg.ServerPort = port
	cfg.LocalSocksPort = socks
	cfg.LocalRelayPort = relay
	cfgMutex.Unlock()

	saveConfig()
	fmt.Println("\n[OK] Server configuration saved successfully to config.json.")

	if atomic.LoadInt32(&running) == 1 {
		fmt.Println("Reloading proxy with new settings...")
		StopProxy()
		time.Sleep(150 * time.Millisecond)
		if err := StartProxy(); err != nil {
			fmt.Printf("[x] Error reloading proxy: %v\n", err)
		} else {
			fmt.Println("[OK] Proxy successfully reloaded.")
		}
	}

	fmt.Println("======================================================================")
	fmt.Print("Press Enter to return to main menu: ")
	_, _ = reader.ReadString('\n')
}

func configureDecoySNI(reader *bufio.Reader) {
	currentCfg := getSnapshotConfig()
	currentSNI := currentCfg.FakeSNI

	fmt.Println("\n======================================================================")
	fmt.Println("                   SELECT DECOY SNI DOMAIN                            ")
	fmt.Println("======================================================================")
	fmt.Printf(" Current Decoy SNI: %s\n\n", currentSNI)
	fmt.Println(" Select from popular high-reputation CDN domains:")
	for idx, item := range popularSNIs {
		fmt.Printf("  %d. %-20s (%s)\n", idx+1, item.Domain, item.Label)
	}
	fmt.Println("  0. Custom Domain (Type manually)")
	fmt.Println("----------------------------------------------------------------------")
	fmt.Printf("Enter choice (0-%d), or type domain directly [%s]: ", len(popularSNIs), currentSNI)

	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	newSNI := currentSNI
	if input != "" {
		if choiceNum, err := strconv.Atoi(input); err == nil {
			if choiceNum >= 1 && choiceNum <= len(popularSNIs) {
				newSNI = popularSNIs[choiceNum-1].Domain
			} else if choiceNum == 0 {
				fmt.Print("Enter custom Decoy SNI domain (e.g. dl.google.com): ")
				cust, _ := reader.ReadString('\n')
				cust = strings.TrimSpace(cust)
				if cust != "" {
					newSNI = cust
				}
			}
		} else {
			newSNI = input
		}
	}

	cfgMutex.Lock()
	cfg.FakeSNI = newSNI
	cfgMutex.Unlock()

	saveConfig()
	fmt.Printf("\n[OK] Decoy SNI successfully set to: %s\n", newSNI)

	if atomic.LoadInt32(&running) == 1 {
		fmt.Println("Applying new Decoy SNI to active proxy...")
		StopProxy()
		time.Sleep(150 * time.Millisecond)
		if err := StartProxy(); err != nil {
			fmt.Printf("[x] Warning reloading proxy: %v\n", err)
		} else {
			fmt.Println("[OK] Proxy successfully reloaded with new Decoy SNI.")
		}
	}

	fmt.Println("======================================================================")
	fmt.Print("Press Enter to return to main menu: ")
	_, _ = reader.ReadString('\n')
}

func configureStrategy(reader *bufio.Reader) {
	currentCfg := getSnapshotConfig()
	currentStrat := currentCfg.Strategy

	fmt.Println("\n======================================================================")
	fmt.Println("                  SELECT EVASION STRATEGY                             ")
	fmt.Println("======================================================================")
	fmt.Printf(" Current Strategy: %s\n\n", currentStrat)
	fmt.Println(" 1. patterniha_desync  : Patterniha Pre-ACK SNI Spoof + Negative Sequence Injection")
	fmt.Println(" 2. tls_fragment      : TLS ClientHello SNI Slicing (Recommended for all ISPs)")
	fmt.Println(" 3. wrong_seq         : TCP Out-of-Window Sequence Evasion")
	fmt.Println(" 4. low_ttl           : Low-TTL Hop-Limit Decoy Packet Injection")
	fmt.Println(" 5. wrong_checksum    : Invalid TCP Checksum Injection")
	fmt.Println(" 6. direct            : Direct TCP Relay (No Evasion)")
	fmt.Println("----------------------------------------------------------------------")
	fmt.Printf("Select Strategy (1-6) [%s]: ", currentStrat)

	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	newStrat := currentStrat
	switch choice {
	case "1", "patterniha", "patterniha_desync":
		newStrat = "patterniha_desync"
	case "2", "fragment", "tls_fragment":
		newStrat = "tls_fragment"
	case "3", "wrong_seq":
		newStrat = "wrong_seq"
	case "4", "low_ttl":
		newStrat = "low_ttl"
	case "5", "wrong_checksum":
		newStrat = "wrong_checksum"
	case "6", "direct":
		newStrat = "direct"
	}

	cfgMutex.Lock()
	cfg.Strategy = newStrat
	cfgMutex.Unlock()

	saveConfig()
	fmt.Printf("\n[OK] Evasion strategy successfully set to: %s\n", newStrat)

	if atomic.LoadInt32(&running) == 1 {
		fmt.Println("Applying new strategy to active proxy...")
		StopProxy()
		time.Sleep(150 * time.Millisecond)
		if err := StartProxy(); err != nil {
			fmt.Printf("[x] Warning reloading proxy: %v\n", err)
		} else {
			fmt.Println("[OK] Proxy successfully reloaded with new strategy.")
		}
	}

	fmt.Println("======================================================================")
	fmt.Print("Press Enter to return to main menu: ")
	_, _ = reader.ReadString('\n')
}

func showV2RayGuide(reader *bufio.Reader) {
	currentCfg := getSnapshotConfig()

	fmt.Println("\n======================================================================")
	fmt.Println("      HOW TO CONFIGURE V2RAY / XRAY / SING-BOX / NEKORAY CLIENTS     ")
	fmt.Println("======================================================================")
	fmt.Println("This client automatically auto-detects and binds ALL your panel ports!")
	fmt.Println()
	fmt.Println("METHOD 1: Multi-Port Direct Relay (Zero Port Editing!)")
	fmt.Println(" 1. In your V2Ray / Singbox client, duplicate ANY of your server profiles.")
	fmt.Println(" 2. Simply change the Address / Server IP to: 127.0.0.1")
	fmt.Println(" 3. KEEP THE SAME PORT! (20443, 20448, 20456, 20444, etc. are all auto-bound!)")
	fmt.Println(" 4. DO NOT change UUID, Path, TLS, or SNI! Leave them exactly as they are.")
	fmt.Println(" 5. Start this terminal client ([1] Open Proxy), then connect in V2Ray.")
	fmt.Println()
	fmt.Println("METHOD 2: SOCKS5 Outbound Proxy (Zero Config Changes!)")
	fmt.Printf(" 1. In v2rayN / Nekoray / Clash, set Outbound / Proxy Server to: 127.0.0.1:%d\n", currentCfg.LocalSocksPort)
	fmt.Println(" 2. You don't even have to change Address or Port! ANY config on ANY port will route!")
	fmt.Println("----------------------------------------------------------------------")
	fmt.Println("Universal Fallback Port:")
	fmt.Printf("  If you prefer a single unified port: Host: 127.0.0.1  |  Port: %d\n", currentCfg.LocalRelayPort)
	fmt.Println("======================================================================")
	fmt.Print("Press Enter to return to main menu: ")
	_, _ = reader.ReadString('\n')
}

func main() {
	serverFlag := flag.String("server", "", "Remote server IP or host")
	portFlag := flag.Int("port", 0, "Remote server port")
	socksFlag := flag.Int("socks", 0, "Local SOCKS5 port")
	relayFlag := flag.Int("relay", 0, "Local TCP relay port")
	sniFlag := flag.String("sni", "", "Fake SNI domain")
	strategyFlag := flag.String("strategy", "", "Evasion strategy (patterniha_desync, tls_fragment, wrong_seq, low_ttl)")
	headlessFlag := flag.Bool("headless", false, "Run in background / headless mode without menu")
	flag.Parse()

	loadConfig()

	if *serverFlag != "" {
		if net.ParseIP(*serverFlag) != nil {
			cfg.ServerIP = *serverFlag
		} else {
			cfg.ServerDomain = *serverFlag
			if ips, err := net.LookupIP(*serverFlag); err == nil && len(ips) > 0 {
				cfg.ServerIP = ips[0].String()
			}
		}
	}
	if *portFlag > 0 {
		cfg.ServerPort = *portFlag
	}
	if *socksFlag > 0 {
		cfg.LocalSocksPort = *socksFlag
	}
	if *relayFlag > 0 {
		cfg.LocalRelayPort = *relayFlag
	}
	if *sniFlag != "" {
		cfg.FakeSNI = *sniFlag
	}
	if *strategyFlag != "" {
		cfg.Strategy = *strategyFlag
	}

	saveConfig()

	if cfg.AutoStart || *headlessFlag {
		_ = StartProxy()
	}

	if *headlessFlag {
		log.Println("[Headless Mode] SNI Spoofing Proxy is running. Press Ctrl+C to terminate.")
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		<-sigChan
		StopProxy()
		return
	}

	reader := bufio.NewReader(os.Stdin)

	for {
		printBanner()
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(strings.ToUpper(input))

		switch input {
		case "1":
			if err := StartProxy(); err != nil {
				fmt.Printf("\n[x] Error starting proxy: %v\n", err)
			} else {
				fmt.Println("\n[OK] Proxy successfully STARTED.")
			}
			time.Sleep(700 * time.Millisecond)

		case "2":
			StopProxy()
			fmt.Println("\n[OK] Proxy successfully STOPPED.")
			time.Sleep(700 * time.Millisecond)

		case "3":
			configureServer(reader)

		case "4":
			configureDecoySNI(reader)

		case "5":
			configureStrategy(reader)

		case "6":
			showV2RayGuide(reader)

		case "7":
			// Just loop to refresh banner

		case "8", "Q", "QUIT", "EXIT":
			StopProxy()
			fmt.Println("\n[OK] Proxy closed. Exiting... Goodbye!")
			return

		default:
			fmt.Println("\n[!] Invalid option. Please enter 1-8 or Q.")
			time.Sleep(800 * time.Millisecond)
		}
	}
}
