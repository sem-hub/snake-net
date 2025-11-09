package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
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
	isServer   bool
	tunAddr    cidrs
	debug      bool
)

var flagAlias = map[string]string{
	"server": "s",
	"config": "c",
	"tun":    "t",
	"debug":  "d",
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
	flag.BoolVar(&isServer, "server", false, "Run as server.")
	flag.Var(&tunAddr, "tun", "Comma separated IPv4 and IPv6 Addresses (CIDR) for Tun interface.")
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
		debug = cfg.Main.Debug
	} else {
		cfg.Main.Debug = debug
		cfg.Log.Main = "Debug"
		cfg.Log.Clients = "Debug"
		cfg.Log.Network = "Debug"
		cfg.Log.Tun = "Debug"
		cfg.Log.Crypt = "Debug"
		cfg.Log.Protocol = "Debug"
		cfg.Log.Route = "Debug"
	}

	logger := configs.InitLogger("main")

	var addr string
	if configFile == "" {
		if isServer {
			cfg.Main.Mode = "server"
		} else {
			cfg.Main.Mode = "client"
		}
		addr = strings.ToLower(flag.Arg(0))
	} else {
		isServer = (strings.ToLower(cfg.Main.Mode) == "server")
		if isServer {
			addr = strings.ToLower(cfg.Main.Protocol+"://"+cfg.Main.LocalAddr) + ":" +
				strconv.Itoa(int(cfg.Main.LocalPort))
		} else {
			addr = strings.ToLower(cfg.Main.Protocol+"://"+cfg.Main.RemoteAddr) + ":" +
				strconv.Itoa(int(cfg.Main.RemotePort))
		}
		logger.Debug(addr)
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
	cfg.Main.Protocol = m[1]
	host := m[2]
	port, err := strconv.Atoi(m[3])
	if err != nil {
		log.Fatalln("Wrong port number", "port", m[3])
	}

	if configFile != "" {
		for _, cidrStr := range cfg.Main.TunAddrStr {
			_, _, err := net.ParseCIDR(cidrStr)
			if err != nil {
				log.Fatalln("Parse error", "CIDR", cidrStr)
			}
			tunAddr = append(tunAddr, cidrStr)
		}
	} else {
		cfg.Main.TunAddrStr = tunAddr
	}

	if len(tunAddr) == 0 {
		log.Fatalln("At least one TUN address (CIDR) is mandatory")
	}

	// Set up TUN interface
	logger.Info("TUN Addresses", "addrs", tunAddr)

	tunIf, err := network.NewTUN("snake", tunAddr, 0)
	if err != nil {
		log.Fatalf("Error creating tun interface: %s", err)
	}

	clients.SetTunInterface(tunIf)

	var t transport.Transport = nil
	switch cfg.Main.Protocol {
	case "udp":
		logger.Info("Using UDP Transport.")
		t = transport.NewUdpTransport()
	case "tcp":
		logger.Info("Using TCP Transport.")
		t = transport.NewTcpTransport()
	default:
		log.Fatalf("Unknown Protocol: %s", cfg.Main.Protocol)
	}

	// Exit only on disconnect or fatal error
	protocol.ResolveAndProcess(t, host, uint32(port))
	t.Close()
}
