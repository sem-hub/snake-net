package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/google/uuid"
	"github.com/sem-hub/snake-net/internal/clients"
	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/crypt/engines"
	"github.com/sem-hub/snake-net/internal/crypt/signature"
	"github.com/sem-hub/snake-net/internal/network"
	"github.com/sem-hub/snake-net/internal/protocol"
)

type cidrs []string
type logType map[string]string

var (
	cfg        *configs.ConfigFile
	configFile string
	isServer   bool
	secret     string
	name       string
	mtu        int
	tunAddr    cidrs
	defaultLog string
	clientId   string
	proto      string
	local      string
	logLevel   logType
	cipher     string
	cert       string
	privKey    string
	signEngine string
	socks5Port int
	socks5User string
	socks5Pass string
	attempts   int
	retryDelay int
	preferIPv6 bool
	preferIPv4 bool
	discovery  bool
)

var flagAlias = map[string]string{
	"attempts":    "a",
	"config":      "c",
	"debug":       "d",
	"log":         "D",
	"cipher":      "e",
	"id":          "i",
	"key":         "k",
	"local":       "l",
	"name":        "n",
	"prefer_ipv4": "4",
	"prefer_ipv6": "6",
	"proto":       "p",
	"server":      "s",
	"tun":         "t",
	"mtu":         "u",
	"socks5":      "x",
	"discovery":   "y",
}

func isFlagPresent(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func checkLogLevel(level string) bool {
	switch strings.ToLower(level) {
	case "trace", "debug", "info", "warn", "error":
		return false
	default:
		return true
	}
}

// New types for flag parsing
func (i *logType) String() string {
	return fmt.Sprint(*i)
}

func (i *logType) Set(value string) error {
	for _, logStr := range strings.Split(value, ",") {
		parts := strings.SplitN(logStr, "=", 2)
		if len(parts) != 2 || checkLogLevel(parts[1]) {
			return fmt.Errorf("invalid log level format: %s", logStr)
		}
		(*i)[parts[0]] = parts[1]
	}
	return nil
}

func (i *cidrs) String() string {
	return fmt.Sprint(*i)
}

func (i *cidrs) Set(value string) error {
	for _, addrStr := range strings.Split(value, ",") {
		_, _, err := net.ParseCIDR(addrStr)
		if err != nil {
			return err
		}
		*i = append(*i, addrStr)
	}
	return nil
}

func init() {
	logLevel = make(map[string]string)
	flag.StringVar(&configFile, "config", "", "Path to config file.")
	flag.BoolVar(&isServer, "server", false, "Server mode (otherwise client mode).")
	flag.StringVar(&secret, "key", "", "Secret key.")
	flag.StringVar(&clientId, "id", "", "Client ID.")
	flag.StringVar(&proto, "proto", "", "Protocol to use (tcp or udp). Overrides config file setting.")
	flag.StringVar(&name, "name", "", "Name of tun interface.")
	flag.IntVar(&mtu, "mtu", network.DefaultMTU, "MTU size.")
	flag.Var(&tunAddr, "tun", "Comma separated IPv4 and IPv6 Addresses (CIDR) for Tun interface.")
	flag.StringVar(&defaultLog, "debug", "Info", "Default logging level for all modules.")
	flag.Var(&logLevel, "log", "Logging levels may be overridden by this.")
	flag.StringVar(&local, "local", "", "Local address (overrides config file).")
	flag.StringVar(&cipher, "cipher", "", "Cipher to use (overrides config file).")
	flag.StringVar(&signEngine, "sign", "", "Signature engine to use (overrides config file).")
	flag.StringVar(&cert, "cert", "", "Path to TLS/DTLS certificate file (overrides config file).")
	flag.StringVar(&privKey, "privkey", "", "Path to TLS/DTLS private key file (overrides config file).")
	flag.IntVar(&socks5Port, "socks5", 0, "Enable SOCKS5 proxy on specified port.")
	flag.StringVar(&socks5User, "socks5user", "", "SOCKS5 proxy username.")
	flag.StringVar(&socks5Pass, "socks5pass", "", "SOCKS5 proxy password.")
	flag.IntVar(&attempts, "attempts", 1, "Number of connection attempts before giving up (0 means infinite).")
	flag.IntVar(&retryDelay, "retry", 5, "Delay in seconds between connection attempts.")
	flag.BoolVar(&preferIPv6, "prefer_ipv6", false, "Prefer IPv6 for remote address resolution.")
	flag.BoolVar(&preferIPv4, "prefer_ipv4", false, "Prefer IPv4 for remote address resolution.")
	flag.BoolVar(&discovery, "discovery", false, "Enable discovery mode.")
	// Setup flag aliases
	for from, to := range flagAlias {
		flagSet := flag.Lookup(from)
		flag.Var(flagSet.Value, to, fmt.Sprintf("alias to %s", flagSet.Name))
	}
}

func main() {
	flag.Parse()
	if flag.NArg() == 0 && configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Special case: UUID generation mode
	if flag.Arg(0) == "uuid" {
		uuid := uuid.New()
		fmt.Println(uuid.String())
		os.Exit(0)
	}

	// ================== Configuration parsing ==================
	// We have a three-step configuration parsing:
	// 1. Set defaults
	// 2. Load config file if specified
	// 3. Override config file settings with command line switches
	var addr string
	cfg = configs.GetConfigFile()
	// Apply defaults
	cfg.Main.IsServer = isServer
	cfg.Main.Protocol = "tcp"
	cfg.Main.DefaultLog = "Info"
	cfg.Main.RetryDelay = retryDelay
	cfg.Main.Attempts = attempts

	if isFlagPresent("prefer_ipv6") || isFlagPresent("6") {
		cfg.Main.PreferIPv6 = true
	}
	if isFlagPresent("prefer_ipv4") || isFlagPresent("4") {
		cfg.Main.PreferIPv4 = true
	}
	if isFlagPresent("discovery") || isFlagPresent("y") {
		cfg.Main.Discovery = true
	}

	// Client may have empty engine and sign engine to get from server
	cfg.Crypt.Engine = ""
	cfg.Crypt.SignEngine = ""

	cfg.Tun.MTU = network.DefaultMTU
	cfg.Tun.Name = "snake"

	cfg.Socks5.Enabled = false
	cfg.Socks5.Port = 1080

	if defaultLog == "" {
		defaultLog = "Info"
	}
	cfg.Log.Main = defaultLog
	cfg.Log.Clients = defaultLog
	cfg.Log.Network = defaultLog
	cfg.Log.Tun = defaultLog
	cfg.Log.Crypt = defaultLog
	cfg.Log.Protocol = defaultLog
	cfg.Log.Route = defaultLog
	cfg.Log.Transport = defaultLog
	cfg.Log.Socks5 = defaultLog
	cfg.Log.ICMP = defaultLog
	cfg.Log.Firewall = defaultLog

	if configFile != "" {
		_, err := toml.DecodeFile(configFile, cfg)
		if err != nil {
			log.Fatalln("Failed to decode config file: ", err)
		}
		// Convert to command line style address: URI. For later parsing.
		if cfg.Main.IsServer {
			addr = strings.ToLower(cfg.Main.Protocol+"://"+cfg.Main.LocalAddr) + ":" +
				strconv.Itoa(int(cfg.Main.LocalPort))
		} else {
			addr = strings.ToLower(cfg.Main.Protocol+"://"+cfg.Main.RemoteAddr) + ":" +
				strconv.Itoa(int(cfg.Main.RemotePort))
		}
	}
	if flag.NArg() > 0 {
		addr = strings.ToLower(flag.Arg(0))
	}

	// Override with command line switches and sanity checks
	logger := configs.InitLogger("main")

	if cfg.Main.IsServer {
		if cfg.Tun == nil || len(cfg.Tun.TunAddrStr) == 0 && len(tunAddr) == 0 {
			logger.Fatal("At least one TUN address (CIDR) is mandatory for server")
		}
	}
	if clientId != "" {
		cfg.Main.ClientId = clientId
	}
	if secret != "" {
		cfg.Main.Secret = secret
	}
	// Default secret if not set
	if cfg.Main.Secret == "" {
		logger.Fatal("Secret key is mandatory")
	}

	if local != "" {
		p := strings.Split(local, ":")
		if len(p) < 2 {
			logger.Fatal("Local address must be in host:port format")
		}
		cfg.Main.LocalAddr = p[0]
		port, err := strconv.Atoi(p[1])
		if err != nil {
			logger.Fatal("Local address parse error", "error", err)
		}
		cfg.Main.LocalPort = uint16(port)
	}
	if cipher != "" {
		cfg.Crypt.Engine = cipher
	}
	if signEngine != "" {
		cfg.Crypt.SignEngine = signEngine
	}
	// Defaults for server
	if cfg.Main.IsServer {
		if cfg.Crypt.Engine == "" {
			cfg.Crypt.Engine = "aes-gcm"
		}
		if cfg.Crypt.SignEngine == "" {
			cfg.Crypt.SignEngine = "ed25519"
		}
	}
	if cert != "" {
		cfg.Tls.CertFile = cert
	}
	if privKey != "" {
		cfg.Tls.KeyFile = privKey
	}
	if socks5Port != 0 {
		cfg.Socks5.Port = socks5Port
		cfg.Socks5.Enabled = true
	}
	if socks5User != "" {
		cfg.Socks5.Username = socks5User
	}
	if socks5Pass != "" {
		cfg.Socks5.Password = socks5Pass
	}
	if mtu != 0 {
		cfg.Tun.MTU = mtu
	}
	if name != "" {
		cfg.Tun.Name = name
	}
	if tunAddr != nil {
		cfg.Tun.TunAddrStr = tunAddr
	}

	// Override log levels with command line switches
	for module, level := range logLevel {
		switch module {
		case "main":
			cfg.Log.Main = level
		case "network":
			cfg.Log.Network = level
		case "tun":
			cfg.Log.Tun = level
		case "route":
			cfg.Log.Route = level
		case "protocol":
			cfg.Log.Protocol = level
		case "clients":
			cfg.Log.Clients = level
		case "crypt":
			cfg.Log.Crypt = level
		case "transport":
			cfg.Log.Transport = level
		case "socks5":
			cfg.Log.Socks5 = level
		case "icmp":
			cfg.Log.ICMP = level
		case "firewall":
			cfg.Log.Firewall = level
		default:
			logger.Warn("Unknown module for log level override", "module", module)
		}
	}

	// Reinit logger with a new level
	logger = configs.ReinitLogger("main")

	proto_regex := `([A-Za-z]+)://`
	ipv4_regex := `(?:[0-9]{1,3}[\.]){3}[0-9]{1,3}`
	ipv6_regex := `\[(?:[0-9a-f]{0,4}:){1,7}[0-9a-f]{0,4}\]`
	fqdn_regex := `(?:(?:(?:[a-z0-9][a-z0-9\-]*[a-z0-9])|[a-z0-9]+)\.)*(?:[a-z]+|xn\-\-[a-z0-9]+)\.?`
	port_regex := `[0-9]{1,5}`
	re := regexp.MustCompile(`(?:` + proto_regex + `)?((?:` + ipv4_regex + `)|(?:` + ipv6_regex + `)|(?:` + fqdn_regex + `))*(?::(` + port_regex + `))?`)
	if !re.MatchString(addr) {
		logger.Fatal("Invalid Address: " + addr + ". proto://host:port format expected.")
	}

	m := re.FindStringSubmatch(addr)
	if m[1] != "" {
		cfg.Main.Protocol = strings.ToLower(m[1])
	}
	host := m[2]
	port := 0
	var err error
	if m[3] != "" {
		port, err = strconv.Atoi(m[3])
		if err != nil {
			logger.Fatal("Wrong port number", "port", m[3])
		}
	}

	logger.Debug("Parsed address", "protocol", cfg.Main.Protocol, "host", host, "port", port)

	if cfg.Main.IsServer {
		cfg.Main.LocalAddr = host
		cfg.Main.LocalPort = uint16(port)
	} else {
		cfg.Main.RemoteAddr = host
		cfg.Main.RemotePort = uint16(port)
	}

	if proto != "" {
		cfg.Main.Protocol = strings.ToLower(proto)
	}

	if configFile != "" {
		for _, cidrStr := range cfg.Tun.TunAddrStr {
			_, _, err := net.ParseCIDR(cidrStr)
			if err != nil {
				logger.Fatal("Parse error", "CIDR", cidrStr)
			}
			tunAddr = append(tunAddr, cidrStr)
		}
	} else {
		cfg.Tun.TunAddrStr = tunAddr
		cfg.Tun.MTU = mtu
		cfg.Tun.Name = name
	}
	if cfg.Main.LocalAddr == "" {
		cfg.Main.LocalAddr = "::"
	}

	if cfg.Crypt.Engine != "" {
		cfg.Crypt.Engine = strings.ToLower(cfg.Crypt.Engine)
		if err != nil || engines.GetEngineType(cfg.Crypt.Engine) == "block" {
			engineMode := strings.Split(cfg.Crypt.Engine, "-")
			if len(engineMode) != 2 {
				logger.Fatal("Unsupported cryptographic engine or invalid engine-mode format, e.g., aes-gcm: " + cfg.Crypt.Engine)
			}
			if !engines.IsEngineSupported(engineMode[0]) {
				logger.Fatal("Unsupported cryptographic engine: " + engineMode[0])
			}
			if !engines.IsModeSupported(engineMode[1]) {
				logger.Fatal("Unsupported cryptographic mode: " + engineMode[1])
			}
		}
	}

	if cfg.Crypt.SignEngine != "" {
		cfg.Crypt.SignEngine = strings.ToLower(cfg.Crypt.SignEngine)
		if !signature.IsEngineSupported(cfg.Crypt.SignEngine) {
			logger.Fatal("Unsupported signature engine: " + cfg.Crypt.SignEngine)
		}
	}

	if len(tunAddr) == 0 && cfg.Main.IsServer {
		logger.Fatal("At least one TUN address (CIDR) is mandatory for server")
	}

	if cfg.Main.ClientId == "" && !cfg.Main.IsServer {
		uuid := uuid.New()
		cfg.Main.ClientId = uuid.String()
		logger.Info("Generated Client ID", "id", cfg.Main.ClientId)
	}
	// ================== Configuration parsed ==================

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Create a context that will be cancelled on signal
	ctx, cancel := context.WithCancel(context.Background())

	// Start processing in a goroutine
	done := make(chan struct{})
	go func() {
		protocol.ResolveAndProcess(ctx)
		close(done)
	}()

	// Wait for either signal or normal completion
	select {
	case sig := <-sigChan:
		logger.Info("Received signal", "signal", sig)
		// Send shutdown command to all clients
		clients.SendShutdownRequest()
		time.Sleep(3 * time.Second) // Give some time for clients to process shutdown
		cancel()
		<-done // Wait for processing to finish
	case <-done:
		cancel() // Clean up context
	}

	logger.Info("Exit")
}
