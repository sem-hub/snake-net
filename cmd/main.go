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
	debug      bool
)

var flagAlias = map[string]string{
	"server": "s",
	"config": "c",
	"tun":    "t",
	"debug":  "d",
}

func init() {
	cfg = configs.GetConfig()
	flag.StringVar(&configFile, "config", "", "Path to config file.")
	flag.BoolVar(&isServer, "server", false, "Run as server.")
	flag.StringVar(&tunAddr, "tun", "", "Address (CIDR) for Tun interface.")
	flag.BoolVar(&debug, "debug", false, "Enable debug mode.")

	for from, to := range flagAlias {
		flagSet := flag.Lookup(from)
		flag.Var(flagSet.Value, to, fmt.Sprintf("alias to %s", flagSet.Name))
	}
}
func main() {
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	if configFile != "" {
		_, err := toml.DecodeFile(configFile, cfg)
		if err != nil {
			log.Fatal(err)
		}
	}

	var level slog.Level = slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	configs.InitLogger(level)
	logger := configs.GetLogger()

	addr := strings.ToLower(flag.Arg(0))

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

	if tunAddr == "" {
		log.Fatal("Tun Address is mandatory")
	}
	cfg.TunAddr = tunAddr

	ips, err := net.LookupIP(host)
	if err != nil {
		log.Fatalf("Error resolving host: %s", err)
		os.Exit(1)
	}

	ip := ips[0]
	logger.Debug("", "ip", ip)

	if !isServer {
		cfg.Mode = "client"
		cfg.RemoteAddr = ip.String()
		cfg.RemotePort = port

	} else {
		cfg.Mode = "server"
		cfg.LocalAddr = ip.String()
		cfg.LocalPort = port
	}

	err = network.SetUpTUN(cfg)
	if err != nil {
		log.Fatalf("Error creating tun interface: %s", err)
	}

	var t transport.Transport = nil
	switch cfg.Protocol {
	case "udp":
		logger.Debug("Using UDP Transport.")
		t = transport.NewUdpTransport(cfg)
	case "tcp":
		logger.Debug("Using TCP Transport.")
		t = transport.NewTcpTransport(cfg)
	default:
		log.Fatalf("Unknown Protocol: %s", cfg.Protocol)
	}
	err = t.Init(cfg)
	if err != nil {
		log.Fatalf("Transport init error %s", err)
	}
	if isServer {
		err = t.WaitConnection(cfg, protocol.ProcessNewClient)
		if err != nil {
			logger.Error("WaitConnection", "Error", err)
		}
		t.Close()
	} else {
		logger.Info("Connect to", "addr", cfg.RemoteAddr, "port", cfg.RemotePort)
		var addr net.Addr
		var err error
		if cfg.Protocol == "tcp" {
			addr, err = net.ResolveTCPAddr("tcp", cfg.RemoteAddr+":"+cfg.RemotePort)
		} else {
			addr, err = net.ResolveUDPAddr("udp", cfg.RemoteAddr+":"+cfg.RemotePort)
		}
		if err != nil {
			log.Fatalf("ResolveIPAddr error: %s", err)
		}
		protocol.ProcessServer(t, addr)
	}
	t.Close()
}
