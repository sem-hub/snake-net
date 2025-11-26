package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
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
	"github.com/sem-hub/snake-net/internal/network"
	"github.com/sem-hub/snake-net/internal/network/transport"
	"github.com/sem-hub/snake-net/internal/protocol"
)

type cidrs []string

var (
	cfg        *configs.ConfigFile
	configFile string
	mode       string
	secret     string
	name       string
	mtu        int
	tunAddr    cidrs
	debug      bool
	clientId   string
	proto      string
	remote     string
	local      string
	cipher     string
	cert       string
	key        string
	signEngine string
)

var flagAlias = map[string]string{
	"mode":   "m",
	"secret": "s",
	"config": "c",
	"tun":    "t",
	"mtu":    "u",
	"name":   "n",
	"debug":  "d",
	"id":     "i",
	"proto":  "p",
	"remote": "r",
	"local":  "l",
	"cipher": "e",
}

// cidrs type for flag parsing
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
	cfg = configs.GetConfigFile()
	flag.StringVar(&configFile, "config", "", "Path to config file.")
	flag.StringVar(&mode, "mode", "client", "Mode: client or server.")
	flag.StringVar(&name, "name", "", "Name of tun interface.")
	flag.StringVar(&secret, "secret", "", "Secret key.")
	flag.StringVar(&clientId, "id", "", "Client ID.")
	flag.StringVar(&proto, "proto", "", "Protocol to use (tcp or udp). Overrides config file setting.")
	flag.IntVar(&mtu, "mtu", network.DefaultMTU, "MTU size.")
	flag.Var(&tunAddr, "tun", "Comma separated IPv4 and IPv6 Addresses (CIDR) for Tun interface.")
	flag.BoolVar(&debug, "debug", false, "Enable debug mode.")
	flag.StringVar(&remote, "remote", "", "Remote address (overrides config file).")
	flag.StringVar(&local, "local", "", "Local address (overrides config file).")
	flag.StringVar(&cipher, "cipher", "", "Cipher to use (overrides config file).")
	flag.StringVar(&cert, "cert", "", "Path to TLS/DTLS certificate file (overrides config file).")
	flag.StringVar(&key, "key", "", "Path to TLS/DTLS key file (overrides config file).")
	flag.StringVar(&signEngine, "sign", "", "Signature engine to use (overrides config file).")

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

	if flag.Arg(0) == "uuid" {
		uuid := uuid.New()
		fmt.Println(uuid.String())
		os.Exit(0)
	}

	// ================== Configuration parsing ==================
	var addr string
	if configFile != "" {
		_, err := toml.DecodeFile(configFile, cfg)
		if err != nil {
			log.Fatal(err)
		}
		// We have both config and command line switch
		// Command line has preference
		if debug {
			cfg.Main.Debug = true
			cfg.Log.Main = "Debug"
			cfg.Log.Clients = "Debug"
			cfg.Log.Network = "Debug"
			cfg.Log.Tun = "Debug"
			cfg.Log.Crypt = "Debug"
			cfg.Log.Protocol = "Debug"
			cfg.Log.Route = "Debug"
			cfg.Log.Transport = "Debug"
		}
		if clientId != "" {
			cfg.Main.ClientId = clientId
		}
		if secret != "" {
			cfg.Main.Secret = secret
		}
		if remote != "" {
			p := strings.Split(remote, ":")
			if len(p) < 2 {
				log.Fatal("Remote address must be in host:port format")
			}
			cfg.Main.RemoteAddr = p[0]
			port, err := strconv.Atoi(p[1])
			if err != nil {
				log.Fatal("Remote address parse error", "error", err)
			}
			cfg.Main.RemotePort = uint16(port)
		}
		if local != "" {
			p := strings.Split(local, ":")
			if len(p) < 2 {
				log.Fatal("Local address must be in host:port format")
			}
			cfg.Main.LocalAddr = p[0]
			port, err := strconv.Atoi(p[1])
			if err != nil {
				log.Fatal("Local address parse error", "error", err)
			}
			cfg.Main.LocalPort = uint16(port)
		}
		if cipher != "" {
			cfg.Crypt.Engine = cipher
		}
		if cert != "" {
			cfg.Tls.CertFile = cert
		}
		if key != "" {
			cfg.Tls.KeyFile = key
		}
		if cfg.Main.Mode == "server" {
			addr = strings.ToLower(cfg.Main.Protocol+"://"+cfg.Main.LocalAddr) + ":" +
				strconv.Itoa(int(cfg.Main.LocalPort))
		} else {
			addr = strings.ToLower(cfg.Main.Protocol+"://"+cfg.Main.RemoteAddr) + ":" +
				strconv.Itoa(int(cfg.Main.RemotePort))
		}
		slog.Debug("", "addr", addr)
	} else {
		cfg.Main.Debug = debug
		if debug {
			cfg.Log.Main = "Debug"
			cfg.Log.Clients = "Debug"
			cfg.Log.Network = "Debug"
			cfg.Log.Tun = "Debug"
			cfg.Log.Crypt = "Debug"
			cfg.Log.Protocol = "Debug"
			cfg.Log.Route = "Debug"
			cfg.Log.Transport = "Debug"
		} else {
			cfg.Log.Main = "Info"
			cfg.Log.Clients = "Info"
			cfg.Log.Network = "Info"
			cfg.Log.Tun = "Info"
			cfg.Log.Crypt = "Info"
			cfg.Log.Protocol = "Info"
			cfg.Log.Route = "Info"
			cfg.Log.Transport = "Info"
		}
		if mode != "server" && mode != "client" {
			log.Fatal("Invalid mode. Use 'client' or 'server'.")
		}

		cfg.Main.Mode = mode
		cfg.Main.Secret = secret
		addr = strings.ToLower(flag.Arg(0))
	}

	logger := configs.InitLogger("main")

	proto_regex := `(tcp|udp)://`
	ipv4_regex := `(?:[0-9]{1,3}[\.]){3}[0-9]{1,3}`
	ipv6_regex := `\[(?:[0-9a-f]{0,4}:){1,7}[0-9a-f]{0,4}\]`
	fqdn_regex := `(?:(?:(?:[a-z0-9][a-z0-9\-]*[a-z0-9])|[a-z0-9]+)\.)*(?:[a-z]+|xn\-\-[a-z0-9]+)\.?`
	port_regex := `[0-9]{1,5}`
	re := regexp.MustCompile(proto_regex + `((?:` + ipv4_regex + `)|(?:` + ipv6_regex + `)|(?:` + fqdn_regex + `))*:(` + port_regex + `)`)
	if !re.MatchString(addr) {
		log.Fatalf("Invalid Address: %s. proto://host:port format expected.\nWhere protocols supported are: tcp, udp", addr)
	}

	m := re.FindStringSubmatch(addr)
	cfg.Main.Protocol = m[1]
	host := m[2]
	port, err := strconv.Atoi(m[3])
	if err != nil {
		log.Fatal("Wrong port number", "port", m[3])
	}

	// Override config protocol if command line switch is used
	if proto != "" {
		cfg.Main.Protocol = proto
	}

	if configFile != "" {
		for _, cidrStr := range cfg.Tun.TunAddrStr {
			_, _, err := net.ParseCIDR(cidrStr)
			if err != nil {
				log.Fatal("Parse error", "CIDR", cidrStr)
			}
			tunAddr = append(tunAddr, cidrStr)
		}
	} else {
		if cfg.Main.Mode == "server" {
			cfg.Main.LocalAddr = host
			cfg.Main.LocalPort = uint16(port)
		} else {
			cfg.Main.RemoteAddr = host
			cfg.Main.RemotePort = uint16(port)
		}
		cfg.Tun.TunAddrStr = tunAddr
		cfg.Tun.MTU = mtu
		cfg.Tun.Name = name
	}
	if cfg.Main.LocalAddr == "" {
		cfg.Main.LocalAddr = "::"
	}

	if len(tunAddr) == 0 {
		log.Fatal("At least one TUN address (CIDR) is mandatory")
	}

	if cfg.Main.ClientId == "" && cfg.Main.Mode == "client" {
		uuid := uuid.New()
		cfg.Main.ClientId = uuid.String()
		logger.Info("Generated Client ID", "id", cfg.Main.ClientId)
	}
	// ================== Configuration parsed ==================

	var t transport.Transport = nil
	switch cfg.Main.Protocol {
	case "udp":
		logger.Info("Using UDP Transport.")
		t = transport.NewUdpTransport()
	case "tcp":
		logger.Info("Using TCP Transport.")
		t = transport.NewTcpTransport()
	case "tls":
		logger.Info("Using TLS Transport.")
		t = transport.NewTlsTransport()
	case "dtls":
		logger.Info("Using DTLS Transport.")
		t = transport.NewDtlsTransport()
	case "quic":
		logger.Info("Using QUIC Transport.")
		t = transport.NewQuicTransport()
	default:
		log.Fatalf("Unknown Protocol: %s", cfg.Main.Protocol)
	}

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Create a context that will be cancelled on signal
	ctx, cancel := context.WithCancel(context.Background())

	// Start processing in a goroutine
	done := make(chan struct{})
	go func() {
		protocol.ResolveAndProcess(ctx, t)
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
	if t != nil {
		t.Close()
	}
}
