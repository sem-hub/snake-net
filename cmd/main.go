package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/network"
	"github.com/sem-hub/snake-net/internal/network/transport"
	"github.com/sem-hub/snake-net/internal/protocol"
)

var (
	cfg        *configs.Config
	configFile string
	isServer   bool
	tunAddr    string
	tunAddr6   string
	debug      bool
)

var flagAlias = map[string]string{
	"server": "s",
	"config": "c",
	"tun":    "t",
	"tun6":   "t6",
	"debug":  "d",
}

func init() {
	cfg = configs.GetConfig()
	flag.StringVar(&configFile, "config", "", "Path to config file.")
	flag.BoolVar(&isServer, "server", false, "Run as server.")
	flag.StringVar(&tunAddr, "tun", "", "Address (CIDR) for Tun interface.")
	flag.StringVar(&tunAddr6, "tun6", "", "Address (CIDR) for Tun interface (IPv6).")
	flag.BoolVar(&debug, "debug", false, "Enable debug mode.")

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

	if configFile != "" {
		_, err := toml.DecodeFile(configFile, cfg)
		if err != nil {
			log.Fatal(err)
		}
		debug = cfg.Debug
	}

	var level slog.Level = slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	configs.InitLogger(level)
	logger := configs.GetLogger()

	var addr string
	if configFile == "" {
		addr = strings.ToLower(flag.Arg(0))
	} else {
		isServer = (cfg.Mode == "server")
		if isServer {
			addr = strings.ToLower(cfg.Protocol + "://" + cfg.LocalAddr + ":" + cfg.LocalPort)
		} else {
			addr = strings.ToLower(cfg.Protocol + "://" + cfg.RemoteAddr + ":" + cfg.RemotePort)
		}
		logger.Info(addr)
	}

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
	cfg.Protocol = m[1]
	host := m[2]
	port := m[3]

	if host == "" {
		if isServer {
			host = "0.0.0.0"
		} else {
			log.Fatal("Remote Address is mandatory for client")
		}
	}
	logger.Debug("URI", "Protocol", cfg.Protocol, "Peer", host, "port", port)

	if configFile == "" {
		cfg.TunAddr = tunAddr
		cfg.TunAddr6 = tunAddr6
	}

	if cfg.TunAddr == "" || cfg.TunAddr6 == "" {
		log.Fatal("Tun and Tun6 Addresses are mandatory")
	}

	if strings.HasPrefix((host), "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	ip := net.ParseIP(host)
	if ip == nil {
		ips, err := net.LookupIP(host)
		if err != nil {
			log.Fatalf("Error resolving host: %s", err)
			os.Exit(1)
		}

		ip = ips[0]
	}
	logger.Debug("", "ip", ip)

	if !isServer {
		cfg.Mode = "client"
		if len(ip) == 16 {
			cfg.RemoteAddr = "[" + ip.String() + "]"
		} else {
			cfg.RemoteAddr = ip.String()
		}
		cfg.RemotePort = port

	} else {
		cfg.Mode = "server"
		if len(ip) == 16 {
			cfg.LocalAddr = "[" + ip.String() + "]"
		} else {
			cfg.LocalAddr = ip.String()
		}
		cfg.LocalPort = port
	}

	err := network.SetUpTUN(cfg)
	if err != nil {
		log.Fatalf("Error creating tun interface: %s", err)
	}

	var t transport.Transport = nil
	switch cfg.Protocol {
	case "udp":
		logger.Debug("Using UDP Transport.")
		t = transport.NewUdpTransport(logger)
	case "tcp":
		logger.Debug("Using TCP Transport.")
		t = transport.NewTcpTransport(logger)
	default:
		log.Fatalf("Unknown Protocol: %s", cfg.Protocol)
	}
	if isServer {
		err = t.Init("server", cfg.RemoteAddr, cfg.RemotePort, cfg.LocalAddr, cfg.LocalPort, protocol.ProcessNewClient)
		if err != nil {
			log.Fatalf("Transport init error %s", err)
		}

		forever := make(chan bool)
		logger.Info("Start server", "addr", cfg.LocalAddr, "port", cfg.LocalPort)
		<-forever
	} else {
		// No callback for client mode
		err = t.Init("client", cfg.RemoteAddr, cfg.RemotePort, cfg.LocalAddr, cfg.LocalPort, nil)
		if err != nil {
			log.Fatalf("Transport init error %s", err)
		}

		logger.Info("Connect to", "addr", cfg.RemoteAddr, "port", cfg.RemotePort)

		protocol.ProcessServer(t, cfg.RemoteAddr, cfg.RemotePort)
	}
	t.Close()
}
