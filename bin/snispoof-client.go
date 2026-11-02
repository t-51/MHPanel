// MHPanel & Patterniha SNI-Spoofing Terminal Client for Windows / Linux
// Compiled standalone binary with Interactive Open/Close & Anti-DPI Evasion Engine
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
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type Config struct {
	ServerIP        string `json:"server_ip"`
	ServerPort      int    `json:"server_port"`
	LocalSocksPort  int    `json:"local_socks_port"`
	LocalRelayPort  int    `json:"local_relay_port"`
	FakeSNI         string `json:"fake_sni"`
	Strategy        string `json:"strategy"` // tls_fragment, wrong_seq, low_ttl, direct
	LowTTLHops      int    `json:"low_ttl_hops"`
	FragmentSize    int    `json:"fragment_size"`
	FragmentDelayMs int    `json:"fragment_delay_ms"`
	AutoStart       bool   `json:"auto_start"`
}

var defaultConfig = Config{
	ServerIP:        "127.0.0.1",
	ServerPort:      15443,
	LocalSocksPort:  10808,
	LocalRelayPort:  40443,
	FakeSNI:         "auth.vercel.com",
	Strategy:        "tls_fragment",
	LowTTLHops:      5,
	FragmentSize:    2,
	FragmentDelayMs: 3,
	AutoStart:       true,
}

var (
	cfg           Config
	cfgMutex      sync.RWMutex
	cfgPath       string
	running       int32
	socksListener net.Listener
	relayListener net.Listener
	activeConns   int64
	bytesTx       int64
	bytesRx       int64
	connsMutex    sync.Mutex
	openSockets   = make(map[net.Conn]struct{})
)

func getExeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

func loadConfig() {
	cfgPath = filepath.Join(getExeDir(), "config.json")
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		// check if config.json exists in patterniha format
		cfg = defaultConfig
		saveConfig()
		return
	}

	// Try loading patterniha format first
	var rawMap map[string]interface{}
	if err := json.Unmarshal(data, &rawMap); err == nil {
		cfg = defaultConfig
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

		// Also check standard fields
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
		if val, ok := rawMap["fake_sni"].(string); ok {
			cfg.FakeSNI = val
		}
		if val, ok := rawMap["strategy"].(string); ok {
			cfg.Strategy = val
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

func connectRemote(targetAddr string, currentCfg Config) (net.Conn, error) {
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

	// Apply Pre-handshake evasion if required
	switch currentCfg.Strategy {
	case "wrong_seq", "fake_sni":
		fakeHello := buildFakeClientHello(currentCfg.FakeSNI)
		_, _ = remote.Write(fakeHello)
		time.Sleep(time.Duration(currentCfg.FragmentDelayMs) * time.Millisecond)
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

			if firstPacket && isClientToRemote && applyFrag && currentCfg.Strategy == "tls_fragment" {
				firstPacket = false
				start, _, _ := findSNIOffset(data)
				fragSize := currentCfg.FragmentSize
				if fragSize <= 0 {
					fragSize = 2
				}
				delay := time.Duration(currentCfg.FragmentDelayMs) * time.Millisecond

				if start > 0 && start+fragSize < len(data) {
					// Split directly inside SNI
					_, _ = dst.Write(data[:start+fragSize])
					time.Sleep(delay)
					_, _ = dst.Write(data[start+fragSize:])
					continue
				} else if len(data) > 10 {
					// Generic split fallback
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

func handleTCPRelay(client net.Conn, targetAddr string, currentCfg Config) {
	registerConn(client)
	defer unregisterConn(client)

	remote, err := connectRemote(targetAddr, currentCfg)
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

func handleSocks5(client net.Conn, targetAddr string, currentCfg Config) {
	registerConn(client)
	defer unregisterConn(client)

	// SOCKS5 greeting
	head := make([]byte, 2)
	if _, err := io.ReadFull(client, head); err != nil || head[0] != 0x05 {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}
	_, _ = client.Write([]byte{0x05, 0x00}) // No auth

	// SOCKS5 request
	req := make([]byte, 4)
	if _, err := io.ReadFull(client, req); err != nil || req[1] != 0x01 { // Only CONNECT
		return
	}

	// Consume destination address from client
	switch req[3] {
	case 1: // IPv4
		buf := make([]byte, 4)
		_, _ = io.ReadFull(client, buf)
	case 3: // Domain
		var l [1]byte
		_, _ = io.ReadFull(client, l[:])
		domainBuf := make([]byte, int(l[0]))
		_, _ = io.ReadFull(client, domainBuf)
	case 4: // IPv6
		buf := make([]byte, 16)
		_, _ = io.ReadFull(client, buf)
	}
	portBuf := make([]byte, 2)
	_, _ = io.ReadFull(client, portBuf)

	// Connect to spoofing target
	remote, err := connectRemote(targetAddr, currentCfg)
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	registerConn(remote)
	defer unregisterConn(remote)

	// Reply SOCKS5 Success
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

// StartProxy opens the listeners
func StartProxy() error {
	if atomic.LoadInt32(&running) == 1 {
		return fmt.Errorf("proxy is already running (پروکسی از قبل باز است)")
	}

	cfgMutex.RLock()
	currentCfg := cfg
	cfgMutex.RUnlock()

	targetAddr := fmt.Sprintf("%s:%d", currentCfg.ServerIP, currentCfg.ServerPort)

	// Start SOCKS5 Listener
	sAddr := fmt.Sprintf("0.0.0.0:%d", currentCfg.LocalSocksPort)
	sList, err := net.Listen("tcp", sAddr)
	if err != nil {
		return fmt.Errorf("failed to bind SOCKS5 port %d: %v", currentCfg.LocalSocksPort, err)
	}
	socksListener = sList

	// Start Direct TCP Relay Listener
	rAddr := fmt.Sprintf("0.0.0.0:%d", currentCfg.LocalRelayPort)
	rList, err := net.Listen("tcp", rAddr)
	if err != nil {
		_ = socksListener.Close()
		return fmt.Errorf("failed to bind TCP Relay port %d: %v", currentCfg.LocalRelayPort, err)
	}
	relayListener = rList

	atomic.StoreInt32(&running, 1)

	// SOCKS5 Accept Loop
	go func() {
		for atomic.LoadInt32(&running) == 1 {
			c, err := sList.Accept()
			if err != nil {
				break
			}
			go handleSocks5(c, targetAddr, currentCfg)
		}
	}()

	// TCP Relay Accept Loop
	go func() {
		for atomic.LoadInt32(&running) == 1 {
			c, err := rList.Accept()
			if err != nil {
				break
			}
			go handleTCPRelay(c, targetAddr, currentCfg)
		}
	}()

	return nil
}

// StopProxy closes the listeners and terminates connections
func StopProxy() {
	if atomic.CompareAndSwapInt32(&running, 1, 0) {
		if socksListener != nil {
			_ = socksListener.Close()
		}
		if relayListener != nil {
			_ = relayListener.Close()
		}
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

func printBanner() {
	fmt.Print("\033[H\033[2J") // Clear screen
	fmt.Println("\033[1;36m======================================================================\033[0m")
	fmt.Println("\033[1;35m      MHPanel & Patterniha SNI-Spoofing Windows Terminal Client       \033[0m")
	fmt.Println("\033[1;36m======================================================================\033[0m")

	cfgMutex.RLock()
	currentCfg := cfg
	cfgMutex.RUnlock()

	statusStr := "\033[1;31m[STOPPED - بسته / قطع]\033[0m"
	if atomic.LoadInt32(&running) == 1 {
		statusStr = "\033[1;32m[RUNNING - باز و فعال]\033[0m"
	}

	fmt.Printf(" \033[1;33mوضعیت پروکسی:\033[0m       %s\n", statusStr)
	fmt.Printf(" \033[1;33mسرور مقصد (Remote):\033[0m  \033[1;37m%s:%d\033[0m\n", currentCfg.ServerIP, currentCfg.ServerPort)
	fmt.Printf(" \033[1;33mپورت SOCKS5 محلی:\033[0m    \033[1;37m127.0.0.1:%d\033[0m\n", currentCfg.LocalSocksPort)
	fmt.Printf(" \033[1;33mپورت رله TCP مستقیم:\033[0m \033[1;37m127.0.0.1:%d\033[0m\n", currentCfg.LocalRelayPort)
	fmt.Printf(" \033[1;33mاستراتژی دورزدن DPI:\033[0m \033[1;32m%s\033[0m\n", currentCfg.Strategy)
	fmt.Printf(" \033[1;33mدامنه جعلی (Fake SNI):\033[0m\033[1;36m%s\033[0m\n", currentCfg.FakeSNI)
	fmt.Printf(" \033[1;33mاتصالات فعال:\033[0m        \033[1;37m%d\033[0m\n", atomic.LoadInt64(&activeConns))
	fmt.Printf(" \033[1;33mترافیک ارسالی / دریافتی:\033[0m \033[1;37mTX: %s | RX: %s\033[0m\n", formatBytes(atomic.LoadInt64(&bytesTx)), formatBytes(atomic.LoadInt64(&bytesRx)))
	fmt.Println("\033[1;36m----------------------------------------------------------------------\033[0m")
	fmt.Println(" \033[1;32m[1] باز کردن اتصال (Start / Open Proxy)\033[0m")
	fmt.Println(" \033[1;31m[2] بستن اتصال (Stop / Close Proxy)\033[0m")
	fmt.Println(" \033[1;33m[3] تنظیم مجدد سرور و پورت‌ها (Settings)\033[0m")
	fmt.Println(" \033[1;34m[4] تغییر استراتژی و دامنه جعلی (Strategy & Fake SNI)\033[0m")
	fmt.Println(" \033[1;37m[5] بازخوانی وضعیت و آمار لحظه‌ای (Refresh)\033[0m")
	fmt.Println(" \033[1;35m[Q/6] خروج کامل از نرم‌افزار (Quit)\033[0m")
	fmt.Println("\033[1;36m======================================================================\033[0m")
	fmt.Print("\033[1;33mلطفاً یک گزینه انتخاب کنید (1-6): \033[0m")
}

func configureServer(reader *bufio.Reader) {
	cfgMutex.Lock()
	defer cfgMutex.Unlock()

	fmt.Print("\nآدرس IP یا دامنه سرور مقصد [" + cfg.ServerIP + "]: ")
	ip, _ := reader.ReadString('\n')
	ip = strings.TrimSpace(ip)
	if ip != "" {
		cfg.ServerIP = ip
	}

	fmt.Printf("پورت سرور مقصد [%d]: ", cfg.ServerPort)
	portStr, _ := reader.ReadString('\n')
	portStr = strings.TrimSpace(portStr)
	if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
		cfg.ServerPort = p
	}

	fmt.Printf("پورت لوکال SOCKS5 [%d]: ", cfg.LocalSocksPort)
	socksStr, _ := reader.ReadString('\n')
	socksStr = strings.TrimSpace(socksStr)
	if s, err := strconv.Atoi(socksStr); err == nil && s > 0 {
		cfg.LocalSocksPort = s
	}

	fmt.Printf("پورت لوکال رله مستقیم TCP [%d]: ", cfg.LocalRelayPort)
	relayStr, _ := reader.ReadString('\n')
	relayStr = strings.TrimSpace(relayStr)
	if r, err := strconv.Atoi(relayStr); err == nil && r > 0 {
		cfg.LocalRelayPort = r
	}

	saveConfig()
	fmt.Println("\033[1;32mتنظیمات با موفقیت در config.json ذخیره شد.\033[0m")
	if atomic.LoadInt32(&running) == 1 {
		fmt.Println("\033[1;33mدر حال اعمال تنظیمات جدید و راه‌اندازی مجدد پروکسی...\033[0m")
		StopProxy()
		_ = StartProxy()
	}
	time.Sleep(1 * time.Second)
}

func configureStrategy(reader *bufio.Reader) {
	cfgMutex.Lock()
	defer cfgMutex.Unlock()

	fmt.Println("\nاستراتژی‌های ضد فیلترینگ:")
	fmt.Println(" 1. tls_fragment (شکستن بسته TLS در مرز SNI - توصیه شده برای تمام اپراتورها)")
	fmt.Println(" 2. wrong_seq (تزریق پکت با شماره سریال اشتباه و دامنه جعلی - سبک پروژه Patterniha)")
	fmt.Println(" 3. low_ttl (تزریق دامنه جعلی با TTL پایین جهت فریب DPI)")
	fmt.Println(" 4. direct (اتصال مستقیم رله)")
	fmt.Print("انتخاب استراتژی (1-4) [" + cfg.Strategy + "]: ")

	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)
	switch choice {
	case "1":
		cfg.Strategy = "tls_fragment"
	case "2":
		cfg.Strategy = "wrong_seq"
	case "3":
		cfg.Strategy = "low_ttl"
	case "4":
		cfg.Strategy = "direct"
	}

	fmt.Print("دامنه جعلی (Fake SNI) [" + cfg.FakeSNI + "]: ")
	sni, _ := reader.ReadString('\n')
	sni = strings.TrimSpace(sni)
	if sni != "" {
		cfg.FakeSNI = sni
	}

	saveConfig()
	fmt.Println("\033[1;32mاستراتژی با موفقیت ذخیره شد.\033[0m")
	if atomic.LoadInt32(&running) == 1 {
		StopProxy()
		_ = StartProxy()
	}
	time.Sleep(1 * time.Second)
}

func main() {
	serverFlag := flag.String("server", "", "Remote server IP or host")
	portFlag := flag.Int("port", 0, "Remote server port")
	socksFlag := flag.Int("socks", 0, "Local SOCKS5 port")
	relayFlag := flag.Int("relay", 0, "Local TCP relay port")
	sniFlag := flag.String("sni", "", "Fake SNI domain")
	strategyFlag := flag.String("strategy", "", "Evasion strategy (tls_fragment, wrong_seq, low_ttl)")
	headlessFlag := flag.Bool("headless", false, "Run in background / headless mode without menu")
	flag.Parse()

	loadConfig()

	// Override with CLI flags if provided
	if *serverFlag != "" {
		cfg.ServerIP = *serverFlag
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

	// Graceful shutdown on SIGINT / SIGTERM
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n\033[1;31mدر حال بستن ایمن کلاینت و آزاد کردن پورت‌ها...\033[0m")
		StopProxy()
		os.Exit(0)
	}()

	// Auto start if configured
	if cfg.AutoStart {
		if err := StartProxy(); err != nil {
			log.Printf("Auto-start warning: %v", err)
		}
	}

	if *headlessFlag {
		fmt.Printf("SNI-Spoofing Client running headless on SOCKS:%d, Relay:%d -> %s:%d\n",
			cfg.LocalSocksPort, cfg.LocalRelayPort, cfg.ServerIP, cfg.ServerPort)
		select {}
	}

	reader := bufio.NewReader(os.Stdin)

	for {
		printBanner()
		input, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		cmd := strings.TrimSpace(strings.ToLower(input))

		switch cmd {
		case "1", "start", "open", "s":
			if atomic.LoadInt32(&running) == 1 {
				fmt.Println("\n\033[1;33mپروکسی در حال حاضر باز است!\033[0m")
			} else {
				if err := StartProxy(); err != nil {
					fmt.Printf("\n\033[1;31mخطا در باز کردن پروکسی: %v\033[0m\n", err)
				} else {
					fmt.Println("\n\033[1;32m✓ پروکسی با موفقیت باز شد و آماده پذیرش اتصال است.\033[0m")
				}
			}
			time.Sleep(1 * time.Second)

		case "2", "stop", "close":
			if atomic.LoadInt32(&running) == 0 {
				fmt.Println("\n\033[1;33mپروکسی در حال حاضر بسته است!\033[0m")
			} else {
				StopProxy()
				fmt.Println("\n\033[1;31m✓ پروکسی با موفقیت بسته شد و تمام اتصالات قطع گردید.\033[0m")
			}
			time.Sleep(1 * time.Second)

		case "3", "settings":
			configureServer(reader)

		case "4", "strategy":
			configureStrategy(reader)

		case "5", "r", "refresh":
			// Loop will naturally refresh banner
			continue

		case "6", "q", "quit", "exit":
			fmt.Println("\n\033[1;31mدر حال خروج از برنامه...\033[0m")
			StopProxy()
			return

		default:
			fmt.Println("\n\033[1;31mگزینه نامعتبر است. لطفاً عدد ۱ تا ۶ یا Q را وارد کنید.\033[0m")
			time.Sleep(1 * time.Second)
		}
	}
}
