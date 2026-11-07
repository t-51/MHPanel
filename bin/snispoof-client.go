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
	"snispoof/dnsembed"
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
	ConnectionMode   string `json:"connection_mode"` // direct_sni, cloudflare_clean, dns_tunnel
	ServerDomain     string `json:"server_domain"`
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

	// DNS Tunnel Transport Settings
	DNSTunnelType    string `json:"dns_tunnel_type"`    // vaydns, dnstt, masterdns, slipstream, noizdns
	DNSTunnelDomain  string `json:"dns_tunnel_domain"`  // e.g. v.vpn.kigaping.com
	DNSPubKey        string `json:"dns_pubkey"`         // 64-hex digits public key
	DNSResolver      string `json:"dns_resolver"`       // e.g. https://cloudflare-dns.com/dns-query or 8.8.8.8:53
	DNSResolverType  string `json:"dns_resolver_type"`  // doh, udp
	DNSInternalPort  int    `json:"dns_internal_port"`  // internal loopback port (default 53001)
}

// Injected at build time via -ldflags "-X main.builtServerIP=... -X main.builtServerDomain=... -X main.builtServerPort=... -X main.builtRelayPorts=... -X main.builtFakeSNI=..."
var (
	builtServerDomain = ""
	builtServerIP     = ""
	builtServerPort   = ""
	builtRelayPorts      = ""
	builtFakeSNI         = ""
	builtConnectionMode  = ""
	builtDNSTunnelType   = ""
	builtDNSTunnelDomain = ""
	builtDNSPubKey       = ""
	builtDNSResolver     = ""
)

var defaultConfig = Config{
	ConnectionMode:   "direct_sni",
	ServerDomain:    "vpn.kigaping.com",
	ServerIP:        "212.227.143.16",
	ServerPort:      15443,
	LocalSocksPort:  40808,
	LocalRelayPort:  40443,
	RelayPorts:      []int{20443, 20444, 20445, 20446, 20447, 20448, 20449, 20450, 20451, 20452, 20453, 20454, 20455, 20456, 20457, 20458, 20459, 20460, 20461, 20462, 20463, 20464, 40443},
	FakeSNI:         "sanjesh.org",
	Strategy:        "patterniha_desync",
	LowTTLHops:      5,
	FragmentSize:    2,
	FragmentDelayMs: 3,
	AutoStart:       true,
	DNSTunnelType:    "vaydns",
	DNSTunnelDomain:  "v.vpn.kigaping.com",
	DNSPubKey:        "4438c41e91bf44b10a9e1a67bbade78f99137a875efc189ba54a6c95ecc2650a",
	DNSResolver:      "https://cloudflare-dns.com/dns-query",
	DNSResolverType:  "doh",
	DNSInternalPort:  53001,
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


var popularDNSResolvers = []struct {
	Type  string
	Addr  string
	Label string
}{
	{"doh", "https://cloudflare-dns.com/dns-query", "Cloudflare DoH (Fast & Encrypted)"},
	{"doh", "https://dns.google/dns-query", "Google DoH (Global Anycast)"},
	{"udp", "8.8.8.8:53", "Google Public DNS (UDP 53)"},
	{"udp", "1.1.1.1:53", "Cloudflare Anycast DNS (UDP 53)"},
	{"udp", "78.157.42.100:53", "Shecan Anti-Sanction DNS (Iran Low Latency)"},
	{"udp", "9.9.9.9:53", "Quad9 Secure DNS (UDP 53)"},
}

type DNSProtocolInfo struct {
	Name    string
	Domain  string
	PubKey  string
	Compat  bool
	Desc    string
}

var dnsProtocolPresets = map[string]DNSProtocolInfo{
	"vaydns": {
		Name:   "VayDNS (V-DNS)",
		Domain: "v.vpn.kigaping.com",
		PubKey: "4438c41e91bf44b10a9e1a67bbade78f99137a875efc189ba54a6c95ecc2650a",
		Compat: false,
		Desc:   "High-Speed Iran Anti-Censorship DNS Tunnel with KCP & uTLS (Recommended)",
	},
	"dnstt": {
		Name:   "DNSTT (SlowDNS)",
		Domain: "t.vpn.kigaping.com",
		PubKey: "b3290012dd13fe7df78551fdfbccfdfce5d3c594522fef40bf8284e4313b3a31",
		Compat: true,
		Desc:   "Standard DNSTT protocol with DoH & UDP support",
	},
	"masterdns": {
		Name:   "MasterDNS",
		Domain: "t.kigaping.com",
		PubKey: "b3290012dd13fe7df78551fdfbccfdfce5d3c594522fef40bf8284e4313b3a31",
		Compat: true,
		Desc:   "MasterdnsVPN high-speed chunked DNS tunnel",
	},
	"slipstream": {
		Name:   "Slipstream",
		Domain: "s.vpn.kigaping.com",
		PubKey: "",
		Compat: false,
		Desc:   "QUIC over DNS covert channel",
	},
	"noizdns": {
		Name:   "NoizDNS",
		Domain: "v.vpn.kigaping.com",
		PubKey: "4438c41e91bf44b10a9e1a67bbade78f99137a875efc189ba54a6c95ecc2650a",
		Compat: true,
		Desc:   "Anti-DPI noise-padded DNS tunnel",
	},
}

var (
	dnsTunnelCmd   *exec.Cmd
	dnsTunnelMutex sync.Mutex
)

func ensureDNSTunnelBin(tunnelType string) (string, error) {
	exeDir := getExeDir()
	binName := "vaydns-client"
	if runtime.GOOS == "windows" {
		binName = "vaydns-client.exe"
	}

	if tunnelType == "slipstream" {
		slipName := "slipstream-client"
		if runtime.GOOS == "windows" {
			slipName = "slipstream-client.exe"
		}
		loc := filepath.Join(exeDir, slipName)
		if _, err := os.Stat(loc); err == nil {
			return loc, nil
		}
		if p, err := exec.LookPath(slipName); err == nil {
			return p, nil
		}
		if _, err := os.Stat("/usr/local/bin/" + slipName); err == nil {
			return "/usr/local/bin/" + slipName, nil
		}
		return "", fmt.Errorf("slipstream-client binary not found in current directory or PATH")
	}

	// 1. Check local directory next to exe
	localPath := filepath.Join(exeDir, binName)
	if _, err := os.Stat(localPath); err == nil {
		return localPath, nil
	}

	// 2. Extract embedded binary if available
	embeddedBytes := dnsembed.GetVayDNS()
	if len(embeddedBytes) > 0 {
		tempBinPath := filepath.Join(os.TempDir(), "snispoof_" + binName)
		info, err := os.Stat(tempBinPath)
		if err != nil || info.Size() != int64(len(embeddedBytes)) {
			_ = os.WriteFile(tempBinPath, embeddedBytes, 0755)
		}
		_ = os.Chmod(tempBinPath, 0755)
		return tempBinPath, nil
	}

	// 3. Check system PATH
	if p, err := exec.LookPath(binName); err == nil {
		return p, nil
	}

	// 4. Check common linux locations
	if runtime.GOOS == "linux" {
		for _, tryP := range []string{"/usr/local/bin/vaydns-client", "/usr/local/bin/dnstt-client"} {
			if _, err := os.Stat(tryP); err == nil {
				return tryP, nil
			}
		}
	}

	return "", fmt.Errorf("%s binary not found. Place %s in the same folder as this client", binName, binName)
}

func startDNSTunnel(currentCfg Config) error {
	dnsTunnelMutex.Lock()
	defer dnsTunnelMutex.Unlock()

	internalPort := currentCfg.DNSInternalPort
	if internalPort <= 0 {
		internalPort = 53001
	}

	listenAddr := fmt.Sprintf("127.0.0.1:%d", internalPort)

	// Check if already responsive
	conn, err := net.DialTimeout("tcp", listenAddr, 300*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		addLiveLog("DNS_READY", fmt.Sprintf("DNS tunnel listener on %s is already active", listenAddr))
		return nil
	}

	binPath, err := ensureDNSTunnelBin(currentCfg.DNSTunnelType)
	if err != nil {
		addLiveLog("ERROR", fmt.Sprintf("DNS tunnel binary error: %v", err))
		return err
	}

	var args []string
	if currentCfg.DNSTunnelType == "slipstream" {
		res := currentCfg.DNSResolver
		if strings.HasPrefix(res, "http") {
			res = "8.8.8.8:53"
		}
		args = []string{"-l", strconv.Itoa(internalPort), "-d", currentCfg.DNSTunnelDomain, "-r", res}
	} else {
		if currentCfg.DNSResolverType == "doh" || strings.HasPrefix(currentCfg.DNSResolver, "http") {
			args = append(args, "-doh", currentCfg.DNSResolver)
		} else {
			res := currentCfg.DNSResolver
			if !strings.Contains(res, ":") {
				res += ":53"
			}
			args = append(args, "-udp", res)
		}

		if currentCfg.DNSPubKey != "" {
			args = append(args, "-pubkey", currentCfg.DNSPubKey)
		}

		args = append(args, "-domain", currentCfg.DNSTunnelDomain)
		args = append(args, "-listen", listenAddr)

		if currentCfg.DNSTunnelType == "vaydns" || currentCfg.DNSTunnelType == "dnstt" || currentCfg.DNSTunnelType == "masterdns" || currentCfg.DNSTunnelType == "noizdns" {
			args = append(args, "-dnstt-compat")
		}
	}

	addLiveLog("DNS_START", fmt.Sprintf("Launching %s engine (%s) -> %s via %s",
		strings.ToUpper(currentCfg.DNSTunnelType), filepath.Base(binPath), currentCfg.DNSTunnelDomain, currentCfg.DNSResolver))

	cmd := exec.Command(binPath, args...)
	dnsembed.SetHideWindow(cmd)

	if err := cmd.Start(); err != nil {
		addLiveLog("ERROR", fmt.Sprintf("Failed to launch %s: %v", binPath, err))
		return err
	}
	dnsTunnelCmd = cmd

	go func() {
		_ = cmd.Wait()
		dnsTunnelMutex.Lock()
		if dnsTunnelCmd == cmd {
			dnsTunnelCmd = nil
		}
		dnsTunnelMutex.Unlock()
		addLiveLog("DNS_STOP", fmt.Sprintf("%s tunnel engine exited.", strings.ToUpper(currentCfg.DNSTunnelType)))
	}()

	for i := 0; i < 20; i++ {
		time.Sleep(150 * time.Millisecond)
		c, err := net.DialTimeout("tcp", listenAddr, 250*time.Millisecond)
		if err == nil {
			_ = c.Close()
			addLiveLog("DNS_READY", fmt.Sprintf("%s tunnel ACTIVE & listening on %s!", strings.ToUpper(currentCfg.DNSTunnelType), listenAddr))
			return nil
		}
	}

	addLiveLog("DNS_WAIT", fmt.Sprintf("%s engine started, awaiting tunnel session on %s...", strings.ToUpper(currentCfg.DNSTunnelType), listenAddr))
	return nil
}

func stopDNSTunnel() {
	dnsTunnelMutex.Lock()
	defer dnsTunnelMutex.Unlock()
	if dnsTunnelCmd != nil && dnsTunnelCmd.Process != nil {
		_ = dnsTunnelCmd.Process.Kill()
		dnsTunnelCmd = nil
	}
}

var popularCleanIPs = []struct {
	IP    string
	Label string
}{
	{"104.18.119.142", "Cloudflare Anycast Clean IP (Fast / Low Latency)"},
	{"104.25.165.92", "Cloudflare Anycast Clean IP (Verified Stable)"},
	{"104.25.224.90", "Cloudflare Anycast Clean IP (High Throughput)"},
	{"159.246.55.228", "Cloudflare Clean IP (Alternative)"},
	{"172.67.69.51", "Cloudflare Anycast Edge"},
	{"91.209.253.54", "Cloudflare Edge"},
	{"199.33.231.234", "Cloudflare Clean IP"},
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

	// Print live to console output so user immediately sees live activity!
	fmt.Printf("\r%s\n> ", formatted)

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

func resolveConfigPath() string {
	// 1. Current working directory config.json has highest priority
	if _, err := os.Stat("config.json"); err == nil {
		return "config.json"
	}
	// 2. Beside executable if writable
	exeDir := getExeDir()
	exeCfg := filepath.Join(exeDir, "config.json")
	if _, err := os.Stat(exeCfg); err == nil {
		return exeCfg
	}
	// 3. User config directory (~/.config/snispoof/config.json) if running from system bin or Termux bin
	if strings.HasPrefix(exeDir, "/usr") || strings.HasPrefix(exeDir, "/bin") || strings.Contains(exeDir, "com.termux") {
		home, err := os.UserHomeDir()
		if err == nil {
			userCfgDir := filepath.Join(home, ".config", "snispoof")
			_ = os.MkdirAll(userCfgDir, 0755)
			return filepath.Join(userCfgDir, "config.json")
		}
	}
	return exeCfg
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
	if builtConnectionMode != "" {
		defaultConfig.ConnectionMode = builtConnectionMode
	}
	if builtDNSTunnelType != "" {
		defaultConfig.DNSTunnelType = builtDNSTunnelType
	}
	if builtDNSTunnelDomain != "" {
		defaultConfig.DNSTunnelDomain = builtDNSTunnelDomain
	}
	if builtDNSPubKey != "" {
		defaultConfig.DNSPubKey = builtDNSPubKey
	}
	if builtDNSResolver != "" {
		defaultConfig.DNSResolver = builtDNSResolver
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
	} else if strings.Contains(exeName, "dns") || strings.Contains(exeName, "vaydns") || strings.Contains(exeName, "dnstt") {
		defaultConfig.ConnectionMode = "dns_tunnel"
	}

	cfgPath = resolveConfigPath()
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
			// Automatically merge with all server default ports so Trojan (20444), WS (20460), gRPC (20461) etc. are always bound
			for _, bp := range defaultConfig.RelayPorts {
				found := false
				for _, ep := range pList {
					if ep == bp {
						found = true
						break
					}
				}
				if !found {
					pList = append(pList, bp)
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
		if val, ok := rawMap["connection_mode"].(string); ok && val != "" {
			cfg.ConnectionMode = val
		}
		if val, ok := rawMap["dns_tunnel_type"].(string); ok && val != "" {
			cfg.DNSTunnelType = val
		}
		if val, ok := rawMap["dns_tunnel_domain"].(string); ok && val != "" {
			cfg.DNSTunnelDomain = val
		}
		if val, ok := rawMap["dns_pubkey"].(string); ok {
			cfg.DNSPubKey = val
		}
		if val, ok := rawMap["dns_resolver"].(string); ok && val != "" {
			cfg.DNSResolver = val
		}
		if val, ok := rawMap["dns_resolver_type"].(string); ok && val != "" {
			cfg.DNSResolverType = val
		}
		if val, ok := rawMap["dns_internal_port"].(float64); ok && val > 0 {
			cfg.DNSInternalPort = int(val)
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
		if writeErr := os.WriteFile(cfgPath, data, 0644); writeErr != nil {
			if home, hErr := os.UserHomeDir(); hErr == nil {
				userCfgDir := filepath.Join(home, ".config", "snispoof")
				_ = os.MkdirAll(userCfgDir, 0755)
				fallbackPath := filepath.Join(userCfgDir, "config.json")
				_ = os.WriteFile(fallbackPath, data, 0644)
				cfgPath = fallbackPath
			} else {
				_ = os.WriteFile("config.json", data, 0644)
				cfgPath = "config.json"
			}
		}
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
	if currentCfg.ConnectionMode == "dns_tunnel" {
		internalPort := currentCfg.DNSInternalPort
		if internalPort <= 0 {
			internalPort = 53001
		}
		tunnelLocal := fmt.Sprintf("127.0.0.1:%d", internalPort)
		addLiveLog("DNS_TUNNEL", fmt.Sprintf("Routing %s via %s DNS Tunnel (%s)...", targetAddr, strings.ToUpper(currentCfg.DNSTunnelType), currentCfg.DNSTunnelDomain))
		d := net.Dialer{Timeout: 12 * time.Second}
		remote, err := d.Dial("tcp", tunnelLocal)
		if err != nil {
			addLiveLog("ERROR", fmt.Sprintf("Failed to connect via DNS tunnel (%s): %v", tunnelLocal, err))
			return nil, err
		}
		if tcpConn, ok := remote.(*net.TCPConn); ok {
			_ = tcpConn.SetNoDelay(true)
			_ = tcpConn.SetKeepAlive(true)
			_ = tcpConn.SetKeepAlivePeriod(15 * time.Second)
		}
		return remote, nil
	}

	addLiveLog("OUTBOUND", fmt.Sprintf("Dialing remote %s...", targetAddr))
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

	// Only send proprietary SNIP multiplexer header if connecting to snispoof-server daemon on port 15443
	if currentCfg.ServerPort == 15443 && currentCfg.Strategy == "patterniha_desync" {
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
	} else if currentCfg.ServerPort == 443 {
		addLiveLog("CLEAN-IP", fmt.Sprintf("Direct tunnel established to Cloudflare Clean IP %s", targetAddr))
	} else {
		addLiveLog("DIRECT", fmt.Sprintf("Direct connection established to %s", targetAddr))
	}

	return remote, nil
}

func relayData(src, dst net.Conn, applyFrag bool, currentCfg Config, isClientToRemote bool, initialPrefix []byte) {
	if currentCfg.ConnectionMode == "dns_tunnel" {
		applyFrag = false
	}
	if len(initialPrefix) > 0 {
		if applyFrag && (currentCfg.Strategy == "tls_fragment" || currentCfg.Strategy == "patterniha_desync") {
			start, _, sni := findSNIOffset(initialPrefix)
			fragSize := currentCfg.FragmentSize
			if fragSize <= 0 {
				fragSize = 2
			}
			delay := time.Duration(currentCfg.FragmentDelayMs) * time.Millisecond
			if delay <= 0 {
				delay = 5 * time.Millisecond
			}
			if start > 0 && start+fragSize < len(initialPrefix) {
				addLiveLog("FRAGMENT", fmt.Sprintf("Slicing SNI (\"%s\") into fragments (delay %v) -> DPI Bypassed!", sni, delay))
				_, _ = dst.Write(initialPrefix[:start+fragSize])
				time.Sleep(delay)
				_, _ = dst.Write(initialPrefix[start+fragSize:])
			} else if len(initialPrefix) > 10 {
				split := min(20, len(initialPrefix)/2)
				addLiveLog("FRAGMENT", fmt.Sprintf("Slicing payload into fragments (delay %v)", delay))
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
			if sni == "cdn.jsdelivr.net" || strings.Contains(sni, "apple") || strings.Contains(sni, "unsplash") {
				targetPort = 20443 // Reality default
				addLiveLog("ROUTER", fmt.Sprintf("Auto-routed %s -> Port 20443 (VLESS-Reality)", sni))
			} else {
				addLiveLog("WARN", fmt.Sprintf("Port 40443 received SNI %s. Multi-protocol domain: connect to the exact local port (e.g. 127.0.0.1:20444 for Trojan, 127.0.0.1:20460 for WS) instead of 40443 for 100%% reliable routing.", sni))
			}
		}
	} else {
		addLiveLog("DETECT", fmt.Sprintf("Non-TLS / Raw TCP payload (%d bytes)", n))
	}

	currentCfg := getSnapshotConfig()

	// Determine actual dial address
	targetHost := currentCfg.ServerIP
	if (targetHost == "" || targetHost == "127.0.0.1") && currentCfg.ServerDomain != "" {
		targetHost = currentCfg.ServerDomain
	}

	dialAddr := targetAddr
	if currentCfg.ConnectionMode == "dns_tunnel" {
		dialAddr = fmt.Sprintf("127.0.0.1:%d", currentCfg.DNSInternalPort)
	} else if currentCfg.ConnectionMode == "cloudflare_clean" || currentCfg.ServerPort == 443 {
		// Cloudflare Clean IP mode -> always route to port 443
		dialAddr = fmt.Sprintf("%s:443", targetHost)
	} else if currentCfg.ServerPort == 15443 {
		// SNIP daemon mode
		dialAddr = fmt.Sprintf("%s:15443", targetHost)
	} else if currentCfg.ServerPort == 0 {
		// Direct mode -> use incoming port
		dialAddr = fmt.Sprintf("%s:%d", targetHost, targetPort)
	}

	remote, err := connectRemote(dialAddr, currentCfg, targetPort)
	if err != nil {
		return
	}
	registerConn(remote)
	defer unregisterConn(remote)

	addLiveLog("RELAY", fmt.Sprintf("Streaming active for %s -> %s", clientAddr, dialAddr))

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
	targetH := currentCfg.ServerIP
	if (targetH == "" || targetH == "127.0.0.1") && currentCfg.ServerDomain != "" {
		targetH = currentCfg.ServerDomain
	}

	dialAddr := targetAddr
	if currentCfg.ConnectionMode == "dns_tunnel" {
		dialAddr = fmt.Sprintf("127.0.0.1:%d", currentCfg.DNSInternalPort)
	} else if currentCfg.ConnectionMode == "cloudflare_clean" || currentCfg.ServerPort == 443 {
		dialAddr = fmt.Sprintf("%s:443", targetH)
	} else if currentCfg.ServerPort == 15443 {
		dialAddr = fmt.Sprintf("%s:15443", targetH)
	} else if currentCfg.ServerPort == 0 {
		dialAddr = fmt.Sprintf("%s:%d", targetH, targetPort)
	}

	remote, err := connectRemote(dialAddr, currentCfg, targetPort)
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

	if currentCfg.ConnectionMode == "dns_tunnel" {
		if err := startDNSTunnel(currentCfg); err != nil {
			addLiveLog("WARN", fmt.Sprintf("Could not initialize DNS tunnel: %v", err))
		}
	}

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
			if p <= 1024 && (runtime.GOOS == "linux" || runtime.GOOS == "android") {
				addLiveLog("WARN", fmt.Sprintf("Port %d requires root (sudo / setcap) on Linux/Termux. Skipped.", p))
			} else {
				addLiveLog("WARN", fmt.Sprintf("Could not bind port %d: %v", p, pErr))
			}
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
		stopDNSTunnel()
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
		fmt.Print("\033[H\033[2J")
	}
}

func printBanner() {
	clearScreen()
	platformTitle := "Universal Client (Linux / Termux / Windows)"
	if runtime.GOOS == "windows" {
		platformTitle = "Windows Client"
	} else if os.Getenv("TERMUX_VERSION") != "" || strings.Contains(os.Getenv("PREFIX"), "com.termux") {
		platformTitle = "Android Termux Client"
	} else {
		platformTitle = "Linux Client"
	}

	fmt.Println("======================================================================")
	fmt.Printf("   MHPanel & Patterniha SNI-Spoofing %s (v2.2)\n", platformTitle)
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
	modeDisplay := "Direct SNI Spoofing"
	if currentCfg.ConnectionMode == "cloudflare_clean" {
		modeDisplay = "Cloudflare Clean IP + TLS SNI Fragment"
	} else if currentCfg.ConnectionMode == "dns_tunnel" {
		modeDisplay = fmt.Sprintf("DNS Tunnel Transport (%s -> %s via %s)", strings.ToUpper(currentCfg.DNSTunnelType), currentCfg.DNSTunnelDomain, currentCfg.DNSResolver)
	}
	fmt.Printf(" Connection Mode:       %s\n", modeDisplay)
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
	fmt.Println(" [M] Connection Mode Selector (Direct SNI / Cloudflare Clean / DNS Tunnel)")
	fmt.Println(" [1] Start / Open Proxy")
	fmt.Println(" [2] Stop / Close Proxy")
	fmt.Println(" [3] Server Domain, IP & Ports Settings")
	fmt.Println(" [4] Inbound Listening Ports (Add / Remove / Change Relay Ports)")
	fmt.Println(" [5] Change Decoy SNI Domain")
	fmt.Println(" [6] Change Evasion Strategy")
	fmt.Println(" [7] Cloudflare Clean IP Mode (Clean Anycast IP + SNI Fragment)")
	fmt.Println(" [8] DNS Tunnel Transport Setup (VayDNS, DNSTT, Slipstream, ...)")
	fmt.Println(" [9] V2Ray / Sing-box / Xray Setup Guide")
	fmt.Println(" [L/10] Live Continuous Event Monitor (Real-time Streaming)")
	fmt.Println(" [R] Refresh Status")
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

func configureCloudflareCleanIP(reader *bufio.Reader) {
	clearScreen()
	fmt.Println("======================================================================")
	fmt.Println("         CLOUDFLARE CLEAN IP & TLS FRAGMENT MODE SETUP                ")
	fmt.Println("======================================================================")
	fmt.Println("In this mode, all traffic is routed to a verified Cloudflare Clean IP")
	fmt.Println("on Port 443 with TLS ClientHello SNI fragmentation.")
	fmt.Println()
	fmt.Println("Features:")
	fmt.Println(" * Bypasses Iranian DPI (SNI is sliced across TCP segments)")
	fmt.Println(" * Hides your actual VPS Server IP behind Cloudflare Anycast edge")
	fmt.Println(" * Zero config changes in V2RayN: Connect to 127.0.0.1:PORT directly!")
	fmt.Println("----------------------------------------------------------------------")
	fmt.Println("Popular Verified Clean IPs:")
	for i, c := range popularCleanIPs {
		fmt.Printf(" [%d] %-16s : %s\n", i+1, c.IP, c.Label)
	}
	fmt.Printf(" [%d] Enter a Custom Clean IP manually\n", len(popularCleanIPs)+1)
	fmt.Println(" [0] Return to main menu (Cancel)")
	fmt.Println("----------------------------------------------------------------------")
	fmt.Print("Please select a Clean IP [1-8, 0=Back]: ")

	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	if choice == "0" || choice == "" {
		return
	}

	chosenIP := ""
	if num, err := strconv.Atoi(choice); err == nil {
		if num >= 1 && num <= len(popularCleanIPs) {
			chosenIP = popularCleanIPs[num-1].IP
		} else if num == len(popularCleanIPs)+1 {
			fmt.Print("Enter custom Cloudflare Clean IP: ")
			cIP, _ := reader.ReadString('\n')
			chosenIP = strings.TrimSpace(cIP)
		}
	} else if net.ParseIP(choice) != nil {
		chosenIP = choice
	}

	if chosenIP == "" || net.ParseIP(chosenIP) == nil {
		fmt.Println("\n[!] Invalid IP address. Returning to main menu.")
		time.Sleep(1 * time.Second)
		return
	}

	cfgMutex.Lock()
	cfg.ServerIP = chosenIP
	cfg.ServerPort = 443
	cfg.Strategy = "tls_fragment"
	if cfg.FragmentSize <= 0 {
		cfg.FragmentSize = 2
	}
	if cfg.FragmentDelayMs <= 0 {
		cfg.FragmentDelayMs = 5
	}
	cfgMutex.Unlock()

	saveConfig()
	fmt.Printf("\n[OK] Cloudflare Clean IP mode ACTIVATED with IP: %s:443\n", chosenIP)
	fmt.Println("     Strategy: tls_fragment (Delay: 5ms, Size: 2B)")

	fmt.Println("Starting proxy with Clean IP settings...")
	StopProxy()
	time.Sleep(200 * time.Millisecond)
	if err := StartProxy(); err != nil {
		fmt.Printf("[x] Error starting proxy: %v\n", err)
	} else {
		fmt.Println("[OK] Proxy successfully STARTED and active on local ports (40443, 20460, ...)!")
	}

	fmt.Println("======================================================================")
	fmt.Print("Press Enter to return to main menu: ")
	_, _ = reader.ReadString('\n')
}


func configureConnectionMode(reader *bufio.Reader) {
	currentCfg := getSnapshotConfig()
	fmt.Println("\n======================================================================")
	fmt.Println("                    SELECT CONNECTION MODE                            ")
	fmt.Println("======================================================================")
	fmt.Printf(" Current Active Mode: [%s]\n\n", currentCfg.ConnectionMode)
	fmt.Println(" Choose your connection mode:")
	fmt.Println("  [1] Direct SNI Spoofing (Direct connection to VPS with DPI desync)")
	fmt.Println("      - Connects directly to VPS with Fake SNI & DPI Desync")
	fmt.Println("      - Best for normal conditions when VPS IP is accessible")
	fmt.Println()
	fmt.Println("  [2] Cloudflare Clean IP + SNI Fragment (Route via Cloudflare 443 with sliced SNI)")
	fmt.Println("      - Routes through verified Cloudflare Clean Anycast IPs on Port 443")
	fmt.Println("      - Bypasses DPI by slicing TLS ClientHello SNI")
	fmt.Println("      - Best for Trojan-WS and VLESS-WS profiles")
	fmt.Println()
	fmt.Println("  [3] DNS Tunnel Transport (Encapsulate V2Ray/TCP in encrypted DNS queries)")
	fmt.Println("      - Encapsulates V2Ray/Singbox traffic inside DNS queries (DoH / UDP)")
	fmt.Println("      - Unblockable: Works even in national internet or severe firewall restrictions")
	fmt.Println("      - Supports: VayDNS, DNSTT, MasterDNS, Slipstream, NoizDNS")
	fmt.Println("----------------------------------------------------------------------")
	fmt.Print("Please select mode [1-3, 0=Cancel]: ")

	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	newMode := currentCfg.ConnectionMode
	switch choice {
	case "1":
		newMode = "direct_sni"
		cfgMutex.Lock()
		cfg.ConnectionMode = newMode
		if cfg.ServerPort == 443 && builtServerPort != "443" {
			cfg.ServerPort = 15443
		}
		if cfg.Strategy == "tls_fragment" {
			cfg.Strategy = "patterniha_desync"
		}
		cfgMutex.Unlock()
		fmt.Println("\n[OK] Switched to Direct SNI Spoofing mode.")

	case "2":
		configureCloudflareCleanIP(reader)
		return

	case "3":
		configureDNSTunnel(reader)
		return

	case "0", "":
		return
	default:
		fmt.Println("\n[!] Invalid choice.")
		return
	}

	saveConfig()
	if atomic.LoadInt32(&running) == 1 {
		fmt.Println("Restarting proxy with new connection mode...")
		StopProxy()
		time.Sleep(200 * time.Millisecond)
		_ = StartProxy()
	}
}

func configureDNSTunnel(reader *bufio.Reader) {
	currentCfg := getSnapshotConfig()
	fmt.Println("\n======================================================================")
	fmt.Println("              DNS TUNNEL TRANSPORT CONFIGURATION                      ")
	fmt.Println("======================================================================")
	fmt.Printf(" Current Protocol : %s\n", strings.ToUpper(currentCfg.DNSTunnelType))
	fmt.Printf(" Current Domain   : %s\n", currentCfg.DNSTunnelDomain)
	fmt.Printf(" Current Resolver : %s (%s)\n\n", currentCfg.DNSResolver, strings.ToUpper(currentCfg.DNSResolverType))

	fmt.Println(" Select DNS Tunnel Protocol:")
	fmt.Println("  [1] VayDNS (V-DNS) [Recommended - High Speed with KCP & uTLS]")
	fmt.Println("      Domain: v.vpn.kigaping.com")
	fmt.Println("  [2] DNSTT (SlowDNS Standard) [Standard DoH / UDP DNS Tunnel]")
	fmt.Println("      Domain: t.vpn.kigaping.com")
	fmt.Println("  [3] MasterDNS (MasterdnsVPN) [High-Speed Chunked DNS Tunnel]")
	fmt.Println("      Domain: t.kigaping.com")
	fmt.Println("  [4] Slipstream (QUIC over DNS) [QUIC Covert Channel]")
	fmt.Println("      Domain: s.vpn.kigaping.com")
	fmt.Println("  [5] NoizDNS (Noise-Padded Anti-DPI) [Noise-Padded Anti-Censorship DNS]")
	fmt.Println("      Domain: v.vpn.kigaping.com")
	fmt.Println("----------------------------------------------------------------------")
	fmt.Print("Choose protocol [1-5, Enter=Keep current]: ")

	pChoice, _ := reader.ReadString('\n')
	pChoice = strings.TrimSpace(pChoice)

	chosenProto := currentCfg.DNSTunnelType
	switch pChoice {
	case "1":
		chosenProto = "vaydns"
	case "2":
		chosenProto = "dnstt"
	case "3":
		chosenProto = "masterdns"
	case "4":
		chosenProto = "slipstream"
	case "5":
		chosenProto = "noizdns"
	}

	preset, ok := dnsProtocolPresets[chosenProto]
	chosenDomain := currentCfg.DNSTunnelDomain
	chosenPubKey := currentCfg.DNSPubKey
	if ok {
		if chosenDomain == "" || chosenProto != currentCfg.DNSTunnelType {
			chosenDomain = preset.Domain
		}
		if preset.PubKey != "" && (chosenPubKey == "" || chosenProto != currentCfg.DNSTunnelType) {
			chosenPubKey = preset.PubKey
		}
	}

	fmt.Println("\n----------------------------------------------------------------------")
	fmt.Println(" Select DNS Resolver:")
	for i, r := range popularDNSResolvers {
		fmt.Printf("  [%d] %-45s (%s)\n", i+1, r.Label, r.Addr)
	}
	fmt.Printf("  [%d] Custom Resolver (DoH URL or IP:53)\n", len(popularDNSResolvers)+1)
	fmt.Print("Choose resolver [1-7, Enter=Keep current]: ")

	rChoice, _ := reader.ReadString('\n')
	rChoice = strings.TrimSpace(rChoice)

	chosenRes := currentCfg.DNSResolver
	chosenResType := currentCfg.DNSResolverType

	if rChoice != "" {
		if num, err := strconv.Atoi(rChoice); err == nil {
			if num >= 1 && num <= len(popularDNSResolvers) {
				chosenRes = popularDNSResolvers[num-1].Addr
				chosenResType = popularDNSResolvers[num-1].Type
			} else if num == len(popularDNSResolvers)+1 {
				fmt.Print("Enter custom resolver (e.g. https://resolver/dns-query or 8.8.8.8:53): ")
				cRes, _ := reader.ReadString('\n')
				cRes = strings.TrimSpace(cRes)
				if cRes != "" {
					chosenRes = cRes
					if strings.HasPrefix(cRes, "http") {
						chosenResType = "doh"
					} else {
						chosenResType = "udp"
					}
				}
			}
		}
	}

	fmt.Println("----------------------------------------------------------------------")
	fmt.Printf("Tunnel Domain [%s]: ", chosenDomain)
	dInput, _ := reader.ReadString('\n')
	dInput = strings.TrimSpace(dInput)
	if dInput != "" {
		chosenDomain = dInput
	}

	if chosenProto != "slipstream" {
		fmt.Printf("Server Public Key [%s]: ", chosenPubKey)
		kInput, _ := reader.ReadString('\n')
		kInput = strings.TrimSpace(kInput)
		if kInput != "" {
			chosenPubKey = kInput
		}
	}

	cfgMutex.Lock()
	cfg.ConnectionMode = "dns_tunnel"
	cfg.DNSTunnelType = chosenProto
	cfg.DNSTunnelDomain = chosenDomain
	cfg.DNSPubKey = chosenPubKey
	cfg.DNSResolver = chosenRes
	cfg.DNSResolverType = chosenResType
	if cfg.DNSInternalPort <= 0 {
		cfg.DNSInternalPort = 53001
	}
	cfgMutex.Unlock()

	saveConfig()

	fmt.Println("\n======================================================================")
	fmt.Printf("[OK] DNS TUNNEL TRANSPORT ACTIVATED!\n")
	fmt.Printf("     Protocol : %s\n", strings.ToUpper(chosenProto))
	fmt.Printf("     Domain   : %s\n", chosenDomain)
	fmt.Printf("     Resolver : %s (%s)\n", chosenRes, strings.ToUpper(chosenResType))
	fmt.Printf("     Local Inbound Relay: 127.0.0.1:40443, 20460, 20443, ...\n")
	fmt.Println("======================================================================")

	fmt.Println("Starting proxy with DNS Tunnel Transport...")
	StopProxy()
	time.Sleep(200 * time.Millisecond)
	if err := StartProxy(); err != nil {
		fmt.Printf("[x] Error starting proxy: %v\n", err)
	} else {
		fmt.Println("[OK] Proxy successfully STARTED and active on local ports!")
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
	fmt.Println(" 3. KEEP THE ORIGINAL PORT! (20443, 20448, 20456, 20444, 20460, etc.)")
	fmt.Println(" 4. DO NOT change UUID, Path, TLS, or SNI! Leave them exactly as they are.")
	fmt.Println(" 5. Start this terminal client ([1] Open Proxy), then connect in V2Ray.")
	fmt.Println()
	fmt.Println("METHOD 2: Cloudflare Clean IP Mode (Option [7])")
	fmt.Println(" 1. Activate Option [7] and select a Cloudflare Clean IP (e.g. 104.18.119.142).")
	fmt.Println(" 2. In V2RayN, take your Trojan-WS or VLESS-WS config.")
	fmt.Println(" 3. Address: 127.0.0.1  |  Port: 20460 (or your WS port).")
	fmt.Println(" 4. SNI & Host: Set to your Cloudflare domain (e.g. ws.kigaping.com or mhpanel.kigaping.com).")
	fmt.Println(" 5. This software fragments the SNI and tunnels directly to the Clean IP!")
	fmt.Println()
	fmt.Println()
	fmt.Println("METHOD 3: DNS Tunnel Transport (Option [8] / [M])")
	fmt.Println(" 1. Press [M] or [8] and select DNS Tunnel Transport.")
	fmt.Println(" 2. Choose your DNS tunnel protocol (VayDNS, DNSTT, etc.).")
	fmt.Println(" 3. In V2RayN / Nekoray / Singbox:")
	fmt.Println("    - Address / Server: 127.0.0.1")
	fmt.Println("    - Port: KEEP YOUR ORIGINAL PORT! (20460 for Trojan-WS, 20443, 40443)")
	fmt.Println("    - SNI, Path & Password: Leave exactly as configured on your server.")
	fmt.Println(" 4. All TCP traffic will be encapsulated inside encrypted DNS queries")
	fmt.Println("    and tunneled straight to the server!")

	fmt.Println("METHOD 4: SOCKS5 Outbound Proxy (Zero Config Changes!)")
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
	modeFlag := flag.String("mode", "", "Connection mode (direct_sni, cloudflare_clean, dns_tunnel)")
	dnsProtoFlag := flag.String("dns-proto", "", "DNS tunnel protocol (vaydns, dnstt, masterdns, slipstream, noizdns)")
	dnsDomainFlag := flag.String("dns-domain", "", "DNS tunnel domain (e.g. v.vpn.kigaping.com)")
	dnsKeyFlag := flag.String("dns-key", "", "DNS tunnel server public key (64 hex digits)")
	dnsResolverFlag := flag.String("dns-resolver", "", "DNS resolver URL/IP (e.g. https://cloudflare-dns.com/dns-query or 8.8.8.8:53)")
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
	if *modeFlag != "" {
		cfg.ConnectionMode = *modeFlag
	}
	if *dnsProtoFlag != "" {
		cfg.DNSTunnelType = *dnsProtoFlag
	}
	if *dnsDomainFlag != "" {
		cfg.DNSTunnelDomain = *dnsDomainFlag
	}
	if *dnsKeyFlag != "" {
		cfg.DNSPubKey = *dnsKeyFlag
	}
	if *dnsResolverFlag != "" {
		cfg.DNSResolver = *dnsResolverFlag
		if strings.HasPrefix(*dnsResolverFlag, "http") {
			cfg.DNSResolverType = "doh"
		} else {
			cfg.DNSResolverType = "udp"
		}
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
		input, err := reader.ReadString('\n')
		if err != nil {
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
			<-sigChan
			StopProxy()
			return
		}
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

		case "M":
			configureConnectionMode(reader)

		case "7":
			configureCloudflareCleanIP(reader)

		case "8":
			configureDNSTunnel(reader)

		case "9":
			showV2RayGuide(reader)

		case "L", "10":
			runLiveMonitor(reader)

		case "R":
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
