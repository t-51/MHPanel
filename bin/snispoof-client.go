// MHPanel & Patterniha SNI-Spoofing Windows Terminal Client (v2.1)
// Cross-platform, standalone binary with Live DPI Logging, Auto-Routing & Evasion Engine
package main

import (
	"bufio"
	"context"
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

func init() {
	// Robust custom DNS resolver for Android/Termux where local /etc/resolv.conf is broken or points to [::1]:53
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			for _, srv := range []string{"8.8.8.8:53", "1.1.1.1:53", "78.157.42.100:53"} {
				if conn, err := d.DialContext(ctx, "udp", srv); err == nil {
					return conn, nil
				}
			}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}
}

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

// Injected at build time via -ldflags "-X main.builtServerIP=... -X main.builtServerDomain=... -X main.builtServerPort=... -X main.builtRelayPorts=... -X main.builtFakeSNI=..."
var (
	builtServerDomain = ""
	builtServerIP     = ""
	builtServerPort   = ""
	builtRelayPorts   = ""
	builtFakeSNI      = ""
)

var defaultConfig = Config{
	ServerDomain:    "vpn.kigaping.com",
	ServerIP:        "212.227.143.16",
	ServerPort:      15443,
	LocalSocksPort:  40808,
	LocalRelayPort:  40443,
	RelayPorts:      []int{443, 8443, 20443, 40443},
	FakeSNI:         "sanjesh.org",
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

// Circular Live Event Log Buffer & File Logger
var (
	recentLogs      []string
	recentLogsMutex sync.Mutex
	logListeners    = make(map[chan string]struct{})
	logListenMutex  sync.Mutex
	logFile         *os.File
	logFileMutex    sync.Mutex
)

func initLogger() {
	logFilePath := filepath.Join(getExeDir(), "snispoof.log")
	f, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		logFile = f
	}
}

func addLiveLog(tag, msg string) {
	ts := time.Now().Format("15:04:05")
	formatted := fmt.Sprintf("[%s] [%-10s] %s", ts, tag, msg)

	recentLogsMutex.Lock()
	recentLogs = append(recentLogs, formatted)
	if len(recentLogs) > 40 {
		recentLogs = recentLogs[len(recentLogs)-40:]
	}
	recentLogsMutex.Unlock()

	// Write to snispoof.log file
	logFileMutex.Lock()
	if logFile != nil {
		_, _ = logFile.WriteString(formatted + "\n")
	}
	logFileMutex.Unlock()

	logListenMutex.Lock()
	for ch := range logListeners {
		select {
		case ch <- formatted:
		default:
		}
	}
	logListenMutex.Unlock()
}

func getRecentLogs(maxCount int) []string {
	recentLogsMutex.Lock()
	defer recentLogsMutex.Unlock()
	if len(recentLogs) <= maxCount {
		res := make([]string, len(recentLogs))
		copy(res, recentLogs)
		return res
	}
	res := make([]string, maxCount)
	copy(res, recentLogs[len(recentLogs)-maxCount:])
	return res
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
	if builtServerDomain != "" {
		defaultConfig.ServerDomain = builtServerDomain
	}
	if builtServerIP != "" {
		defaultConfig.ServerIP = builtServerIP
	}
	if builtServerPort != "" {
		if p, err := strconv.Atoi(builtServerPort); err == nil && p > 0 {
			defaultConfig.ServerPort = p
		}
	}
	if builtFakeSNI != "" {
		defaultConfig.FakeSNI = builtFakeSNI
	}
	if builtRelayPorts != "" {
		var pList []int
		for _, part := range strings.Split(builtRelayPorts, ",") {
			part = strings.TrimSpace(part)
			if p, err := strconv.Atoi(part); err == nil && p > 0 && p <= 65535 {
				pList = append(pList, p)
			}
		}
		if len(pList) > 0 {
			defaultConfig.RelayPorts = pList
		}
	}

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
	addLiveLog("OUTBOUND", fmt.Sprintf("Dialing remote server %s...", targetAddr))
	d := net.Dialer{Timeout: 8 * time.Second}
	remote, err := d.Dial("tcp", targetAddr)
	if err != nil {
		addLiveLog("ERROR", fmt.Sprintf("Failed to connect to %s: %v", targetAddr, err))
		return nil, err
	}

	if tcpConn, ok := remote.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(15 * time.Second)
	}

	var fakeHello []byte
	switch currentCfg.Strategy {
	case "patterniha_desync", "wrong_seq", "fake_sni", "low_ttl":
		fakeHello = buildFakeClientHello(currentCfg.FakeSNI)
	}

	fakeLen := len(fakeHello)
	// Protocol Header: MAGIC 'SNIP' (4B) + targetPort (2B uint16) + fakeLen (2B uint16)
	routingHead := []byte{
		0x53, 0x4e, 0x49, 0x50,
		byte(targetPort >> 8), byte(targetPort & 0xff),
		byte(fakeLen >> 8), byte(fakeLen & 0xff),
	}
	_, _ = remote.Write(routingHead)

	if fakeLen > 0 {
		addLiveLog("DESYNC", fmt.Sprintf("Injected Decoy SNI: \"%s\" (%d bytes) -> Spoofing DPI filter", currentCfg.FakeSNI, fakeLen))
		_, _ = remote.Write(fakeHello)
		delay := time.Duration(currentCfg.FragmentDelayMs) * time.Millisecond
		if delay <= 0 {
			delay = 3 * time.Millisecond
		}
		time.Sleep(delay)
	}

	addLiveLog("TUNNEL", fmt.Sprintf("Remote tunnel established -> Server target: 127.0.0.1:%d", targetPort))
	return remote, nil
}

func relayData(src, dst net.Conn, applyFrag bool, currentCfg Config, isClientToRemote bool, initialPrefix []byte) {
	if len(initialPrefix) > 0 {
		if applyFrag && (currentCfg.Strategy == "tls_fragment" || currentCfg.Strategy == "patterniha_desync") {
			start, _, _ := findSNIOffset(initialPrefix)
			fragSize := currentCfg.FragmentSize
			if fragSize <= 0 {
				fragSize = 2
			}
			delay := time.Duration(currentCfg.FragmentDelayMs) * time.Millisecond
			if start > 0 && start+fragSize < len(initialPrefix) {
				addLiveLog("FRAGMENT", fmt.Sprintf("Slicing SNI into fragments (delay %v)", delay))
				_, _ = dst.Write(initialPrefix[:start+fragSize])
				time.Sleep(delay)
				_, _ = dst.Write(initialPrefix[start+fragSize:])
			} else if len(initialPrefix) > 10 {
				split := min(20, len(initialPrefix)/2)
				_, _ = dst.Write(initialPrefix[:split])
				time.Sleep(delay)
				_, _ = dst.Write(initialPrefix[split:])
			} else {
				_, _ = dst.Write(initialPrefix)
			}
		} else {
			_, _ = dst.Write(initialPrefix)
		}
		if isClientToRemote {
			atomic.AddInt64(&bytesTx, int64(len(initialPrefix)))
		} else {
			atomic.AddInt64(&bytesRx, int64(len(initialPrefix)))
		}
	}

	buf := make([]byte, 32768)
	for {
		nr, err := src.Read(buf)
		if nr > 0 {
			data := buf[:nr]
			if isClientToRemote {
				atomic.AddInt64(&bytesTx, int64(nr))
			} else {
				atomic.AddInt64(&bytesRx, int64(nr))
			}
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func handleTCPRelay(client net.Conn, targetAddr string, defaultPort int) {
	registerConn(client)
	defer unregisterConn(client)

	clientAddr := client.RemoteAddr().String()
	addLiveLog("INBOUND", fmt.Sprintf("New connection from %s", clientAddr))

	// Peek first packet to detect SNI and determine destination port
	firstBuf := make([]byte, 4096)
	_ = client.SetReadDeadline(time.Now().Add(4 * time.Second))
	n, err := client.Read(firstBuf)
	_ = client.SetReadDeadline(time.Time{})
	if err != nil || n == 0 {
		addLiveLog("ERROR", fmt.Sprintf("Client %s sent no handshake data", clientAddr))
		return
	}
	initialData := firstBuf[:n]

	targetPort := defaultPort
	start, _, sni := findSNIOffset(initialData)
	if start > 0 && sni != "" {
		addLiveLog("DETECT", fmt.Sprintf("Client TLS ClientHello: SNI = \"%s\"", sni))
		if defaultPort == 40443 {
			// Auto-route based on SNI if connected on universal port 40443
			if sni == "mhpanel.kigaping.com" {
				targetPort = 20456 // VLESS-TCP-TLS default
				addLiveLog("ROUTER", "Auto-routed mhpanel.kigaping.com -> Port 20456 (VLESS-TCP-TLS)")
			} else if sni == "cdn.jsdelivr.net" || strings.Contains(sni, "apple") || strings.Contains(sni, "unsplash") {
				targetPort = 20443 // Reality default
				addLiveLog("ROUTER", fmt.Sprintf("Auto-routed %s -> Port 20443 (VLESS-Reality)", sni))
			}
		}
	} else {
		addLiveLog("DETECT", fmt.Sprintf("Non-TLS / Raw TCP payload (%d bytes)", n))
	}

	currentCfg := getSnapshotConfig()
	remote, err := connectRemote(targetAddr, currentCfg, targetPort)
	if err != nil {
		return
	}
	registerConn(remote)
	defer unregisterConn(remote)

	addLiveLog("RELAY", fmt.Sprintf("Bidirectional proxy streaming active for %s", clientAddr))

	done := make(chan struct{}, 2)
	go func() {
		relayData(client, remote, true, currentCfg, true, initialData)
		done <- struct{}{}
	}()
	go func() {
		relayData(remote, client, false, currentCfg, false, nil)
		done <- struct{}{}
	}()
	<-done
	addLiveLog("CLOSE", fmt.Sprintf("Connection closed for %s", clientAddr))
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

	var targetHost string
	switch req[3] {
	case 1:
		buf := make([]byte, 4)
		_, _ = io.ReadFull(client, buf)
		targetHost = net.IP(buf).String()
	case 3:
		var l [1]byte
		_, _ = io.ReadFull(client, l[:])
		domainBuf := make([]byte, int(l[0]))
		_, _ = io.ReadFull(client, domainBuf)
		targetHost = string(domainBuf)
	case 4:
		buf := make([]byte, 16)
		_, _ = io.ReadFull(client, buf)
		targetHost = net.IP(buf).String()
	}
	portBuf := make([]byte, 2)
	_, _ = io.ReadFull(client, portBuf)
	targetPort := int(portBuf[0])<<8 | int(portBuf[1])
	if targetPort <= 0 {
		targetPort = 20443
	}

	addLiveLog("SOCKS5", fmt.Sprintf("SOCKS5 Request to %s:%d", targetHost, targetPort))

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
		relayData(client, remote, true, currentCfg, true, nil)
		done <- struct{}{}
	}()
	go func() {
		relayData(remote, client, false, currentCfg, false, nil)
		done <- struct{}{}
	}()
	<-done
}

func StartProxy() error {
	if atomic.LoadInt32(&running) == 1 {
		return fmt.Errorf("proxy is already running")
	}

	currentCfg := getSnapshotConfig()
	// Prefer direct ServerIP to avoid DNS lookup issues/poisoning on Android Termux
	targetHost := currentCfg.ServerIP
	if (targetHost == "" || targetHost == "127.0.0.1") && currentCfg.ServerDomain != "" {
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

	addLiveLog("SYSTEM", fmt.Sprintf("Proxy Started! Listening on SOCKS5 :%d & Relay :%d", currentCfg.LocalSocksPort, currentCfg.LocalRelayPort))

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

	// Universal fallback TCP Relay listener (:40443)
	go func() {
		for atomic.LoadInt32(&running) == 1 {
			c, err := rList.Accept()
			if err != nil {
				break
			}
			go handleTCPRelay(c, targetAddr, 40443)
		}
	}()

	// Auto-bind multi-port relay listeners on 127.0.0.1 for every panel inbound port
	extraListenersMutex.Lock()
	extraListeners = nil
	for _, p := range currentCfg.RelayPorts {
		// Do not bind invalid ports or client app reserved local proxy ports
		if p <= 0 || p > 65535 || p == currentCfg.LocalSocksPort || p == currentCfg.LocalRelayPort || p == 10808 || p == 10809 || p == 7890 || p == 2080 {
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
			addLiveLog("PORT", fmt.Sprintf("Bound local relay 127.0.0.1:%d -> Remote:%d", p, targetP))
		} else {
			addLiveLog("WARN", fmt.Sprintf("Could not bind port %d: %v", p, pErr))
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
		addLiveLog("SYSTEM", "Proxy Stopped.")
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
	fmt.Println("   MHPanel & Patterniha SNI-Spoofing Windows Terminal Client (v2.1)   ")
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

	// Print Live Activity Log (Last 5 events)
	fmt.Println("----------------------------------------------------------------------")
	fmt.Println(" [Recent DPI & Connection Activity] (Real-time events):")
	recent := getRecentLogs(5)
	if len(recent) == 0 {
		fmt.Println("   (No connections yet. Send traffic from V2Ray/Singbox to see logs)")
	} else {
		for _, l := range recent {
			fmt.Printf("   %s\n", l)
		}
	}

	fmt.Println("----------------------------------------------------------------------")
	fmt.Println(" [1] Start / Open Proxy")
	fmt.Println(" [2] Stop / Close Proxy")
	fmt.Println(" [3] Server Domain, IP & Ports Settings")
	fmt.Println(" [4] Inbound Listening Ports (Add / Remove / Change Relay Ports)")
	fmt.Println(" [5] Change Decoy SNI Domain")
	fmt.Println(" [6] Change Evasion Strategy")
	fmt.Println(" [7] V2Ray / Sing-box / Xray Setup Guide")
	fmt.Println(" [L/8] Live Continuous Event Monitor (Real-time Streaming)")
	fmt.Println(" [9] Refresh Status")
	fmt.Println(" [Q/0] Quit / Exit")
	fmt.Println("======================================================================")
	fmt.Print("Please select an option: ")
}

func runLiveMonitor(reader *bufio.Reader) {
	clearScreen()
	fmt.Println("======================================================================")
	fmt.Println("               LIVE REAL-TIME DPI & CONNECTION MONITOR                ")
	fmt.Println("======================================================================")
	fmt.Println("Streaming live traffic, DPI evasion, SNI spoofing and relay events...")
	fmt.Println("Press [Enter] at any time to return to the main menu.")
	fmt.Println("----------------------------------------------------------------------")

	ch := make(chan string, 100)
	logListenMutex.Lock()
	logListeners[ch] = struct{}{}
	logListenMutex.Unlock()

	defer func() {
		logListenMutex.Lock()
		delete(logListeners, ch)
		logListenMutex.Unlock()
	}()

	// Print past logs first
	for _, l := range getRecentLogs(10) {
		fmt.Println(l)
	}

	done := make(chan struct{})
	go func() {
		_, _ = reader.ReadString('\n')
		close(done)
	}()

	for {
		select {
		case msg := <-ch:
			fmt.Println(msg)
		case <-done:
			return
		}
	}
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

	var pStrs []string
	for _, p := range currentCfg.RelayPorts {
		pStrs = append(pStrs, strconv.Itoa(p))
	}
	fmt.Printf("Enter Inbound Relay Ports (comma-separated, Enter to keep) [%s]: ", strings.Join(pStrs, ", "))
	portsInput, _ := reader.ReadString('\n')
	portsInput = strings.TrimSpace(portsInput)
	var newRelayPorts []int
	if portsInput != "" {
		for _, part := range strings.Split(portsInput, ",") {
			part = strings.TrimSpace(part)
			if p, err := strconv.Atoi(part); err == nil && p > 0 && p <= 65535 {
				newRelayPorts = append(newRelayPorts, p)
			}
		}
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
	if len(newRelayPorts) > 0 {
		cfg.RelayPorts = newRelayPorts
	}
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

func configureRelayPorts(reader *bufio.Reader) {
	currentCfg := getSnapshotConfig()

	fmt.Println("\n======================================================================")
	fmt.Println("          INBOUND LISTENING & RELAY PORTS CONFIGURATION               ")
	fmt.Println("======================================================================")
	var pStrs []string
	for _, p := range currentCfg.RelayPorts {
		pStrs = append(pStrs, strconv.Itoa(p))
	}
	fmt.Printf("Current Inbound Ports: %s\n\n", strings.Join(pStrs, ", "))
	fmt.Println("These ports are opened on 127.0.0.1 on this machine. Your VPN clients")
	fmt.Println("(V2RayN, Nekoray, Sing-box) can connect to 127.0.0.1:PORT directly.")
	fmt.Println("----------------------------------------------------------------------")
	fmt.Println(" [1] Add new port(s) (e.g. 443 or 443, 8443, 2083)")
	fmt.Println(" [2] Remove a port from the list (take out of default)")
	fmt.Println(" [3] Replace with a completely new list of ports")
	fmt.Println(" [4] Reset to default panel ports")
	fmt.Println(" [0] Return to main menu")
	fmt.Println("----------------------------------------------------------------------")
	fmt.Print("Please select an option [1-4, 0=Back]: ")

	opt, _ := reader.ReadString('\n')
	opt = strings.TrimSpace(opt)

	switch opt {
	case "1":
		fmt.Print("Enter port(s) to add (comma-separated, e.g. 443, 8443): ")
		in, _ := reader.ReadString('\n')
		in = strings.TrimSpace(in)
		added := 0
		portSet := make(map[int]bool)
		for _, p := range currentCfg.RelayPorts {
			portSet[p] = true
		}
		for _, part := range strings.Split(in, ",") {
			part = strings.TrimSpace(part)
			if p, err := strconv.Atoi(part); err == nil && p > 0 && p <= 65535 {
				if !portSet[p] {
					currentCfg.RelayPorts = append(currentCfg.RelayPorts, p)
					portSet[p] = true
					added++
				}
			}
		}
		if added > 0 {
			cfgMutex.Lock()
			cfg.RelayPorts = currentCfg.RelayPorts
			cfgMutex.Unlock()
			saveConfig()
			fmt.Printf("\n[OK] Added %d port(s) successfully.\n", added)
		} else {
			fmt.Println("\n[!] No valid new ports entered.")
		}

	case "2":
		fmt.Printf("Current ports: %s\n", strings.Join(pStrs, ", "))
		fmt.Print("Enter port number to remove: ")
		in, _ := reader.ReadString('\n')
		in = strings.TrimSpace(in)
		if remPort, err := strconv.Atoi(in); err == nil {
			var updated []int
			found := false
			for _, p := range currentCfg.RelayPorts {
				if p == remPort {
					found = true
				} else {
					updated = append(updated, p)
				}
			}
			if found {
				cfgMutex.Lock()
				cfg.RelayPorts = updated
				cfgMutex.Unlock()
				saveConfig()
				fmt.Printf("\n[OK] Port %d removed from inbound listening ports.\n", remPort)
			} else {
				fmt.Printf("\n[!] Port %d was not in the list.\n", remPort)
			}
		}

	case "3":
		fmt.Print("Enter complete new list of ports (comma-separated, e.g. 443, 8443, 20443, 40443): ")
		in, _ := reader.ReadString('\n')
		in = strings.TrimSpace(in)
		var newPorts []int
		for _, part := range strings.Split(in, ",") {
			part = strings.TrimSpace(part)
			if p, err := strconv.Atoi(part); err == nil && p > 0 && p <= 65535 {
				newPorts = append(newPorts, p)
			}
		}
		if len(newPorts) > 0 {
			cfgMutex.Lock()
			cfg.RelayPorts = newPorts
			cfgMutex.Unlock()
			saveConfig()
			fmt.Println("\n[OK] Inbound listening ports list updated successfully.")
		} else {
			fmt.Println("\n[!] No valid ports entered.")
		}

	case "4":
		defaultPorts := []int{20443, 20452, 20453, 20451, 20454, 20455, 20456, 20448, 20457, 20458, 20459, 20444, 20460, 20461, 20462, 40443}
		cfgMutex.Lock()
		cfg.RelayPorts = defaultPorts
		cfgMutex.Unlock()
		saveConfig()
		fmt.Println("\n[OK] Inbound listening ports reset to defaults.")

	case "0", "":
		return

	default:
		fmt.Println("\n[!] Invalid choice.")
	}

	if atomic.LoadInt32(&running) == 1 {
		fmt.Println("Reloading proxy listeners with new inbound ports...")
		StopProxy()
		time.Sleep(150 * time.Millisecond)
		if err := StartProxy(); err != nil {
			fmt.Printf("[x] Warning reloading proxy: %v\n", err)
		} else {
			fmt.Println("[OK] Proxy successfully reloaded with updated listening ports.")
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
	fmt.Println(" 1. patterniha_desync  : Patterniha Pre-ACK SNI Spoof (Decoy injected & stripped)")
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
	fmt.Println("METHOD 1: Multi-Port Direct Relay (Recommended)")
	fmt.Println(" 1. In your V2Ray / Singbox client, duplicate ANY of your server profiles.")
	fmt.Println(" 2. Simply change the Address / Server IP to: 127.0.0.1")
	fmt.Println(" 3. KEEP THE ORIGINAL PORT! (20443, 20448, 20456, 20444, etc. are all auto-bound!)")
	fmt.Println(" 4. DO NOT change UUID, Path, TLS, or SNI! Leave them exactly as they are.")
	fmt.Println(" 5. Start this terminal client ([1] Open Proxy), then connect in V2Ray.")
	fmt.Println()
	fmt.Println("METHOD 2: Universal Relay Port (:40443)")
	fmt.Println(" 1. Address: 127.0.0.1  |  Port: 40443")
	fmt.Println(" 2. Client will automatically inspect the SNI and route to the correct inbound!")
	fmt.Println()
	fmt.Println("METHOD 3: SOCKS5 Outbound Proxy (Zero Config Changes!)")
	fmt.Printf(" 1. In v2rayN / Nekoray / Clash, set Outbound / Proxy Server to: 127.0.0.1:%d\n", currentCfg.LocalSocksPort)
	fmt.Println(" 2. You don't even have to change Address or Port! ANY config on ANY port will route!")
	fmt.Println("======================================================================")
	fmt.Print("Press Enter to return to main menu: ")
	_, _ = reader.ReadString('\n')
}

func main() {
	initLogger()
	serverFlag := flag.String("server", "", "Remote server IP or host")
	portFlag := flag.Int("port", 0, "Remote server port")
	socksFlag := flag.Int("socks", 0, "Local SOCKS5 port")
	relayFlag := flag.Int("relay", 0, "Local TCP relay port")
	portsFlag := flag.String("ports", "", "Comma-separated list of inbound relay ports to listen on (e.g. 443,8443,20443,40443)")
	relayPortsFlag := flag.String("relay-ports", "", "Alias for -ports")
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
	if *portsFlag != "" || *relayPortsFlag != "" {
		pStr := *portsFlag
		if pStr == "" {
			pStr = *relayPortsFlag
		}
		var newPorts []int
		for _, part := range strings.Split(pStr, ",") {
			part = strings.TrimSpace(part)
			if p, err := strconv.Atoi(part); err == nil && p > 0 && p <= 65535 {
				newPorts = append(newPorts, p)
			}
		}
		if len(newPorts) > 0 {
			cfg.RelayPorts = newPorts
		}
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
			configureRelayPorts(reader)

		case "5":
			configureDecoySNI(reader)

		case "6":
			configureStrategy(reader)

		case "7":
			showV2RayGuide(reader)

		case "L", "8":
			runLiveMonitor(reader)

		case "9":
			// Just loop to refresh banner

		case "0", "Q", "QUIT", "EXIT":
			StopProxy()
			fmt.Println("\n[OK] Proxy closed. Exiting... Goodbye!")
			return

		default:
			fmt.Println("\n[!] Invalid option. Please enter 0-9 or L.")
			time.Sleep(800 * time.Millisecond)
		}
	}
}
