package main

import (
	"flag"
	"fmt"
	"log"
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
)

var flagAlias = map[string]string{
	"server": "s",
	"config": "c",
	"tun":    "t",
}

func init() {
	cfg = configs.NewConfig()
	flag.StringVar(&configFile, "config", "", "Path to config file.")
	flag.BoolVar(&isServer, "server", false, "Run as server.")
	flag.StringVar(&tunAddr, "tun", "", "Address for Tun interface.")

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

	addr := strings.ToLower(flag.Arg(0))

	proto_regex := `(tcp|udp)://`
	ipv4_regex := `(?:[0-9]{1,3}[\.]){3}[0-9]{1,3}`
	ipv6_regex := `\[(?:[0-9a-f]{0,4}:){1,7}[0-9a-f]{0,4}\]`
	fqdn_regex := `(?:(?:(?:[a-z0-9][a-z0-9\-]*[a-z0-9])|[a-z0-9]+)\.)*(?:[a-z]+|xn\-\-[a-z0-9]+)\.?`
	port_regex := `[0-9]{1,5}`
	re := regexp.MustCompile(proto_regex + `((?:` + ipv4_regex + `)|(?:` + ipv6_regex + `)|(?:` + fqdn_regex + `)):(` + port_regex + `)`)
	if !re.MatchString(addr) {
		fmt.Printf("Invalid Address: %s. proto://host:port format expected\n", addr)
		os.Exit(1)
	}

	m := re.FindStringSubmatch(addr)
	cfg.Protocol = m[1]
	host := m[2]
	port := m[3]

	if tunAddr == "" {
		fmt.Println("Tun Address is mandatory")
		os.Exit(1)
	}
	cfg.TunAddr = tunAddr

	fmt.Printf("Protocol: %s\n", cfg.Protocol)
	fmt.Printf("Peer Addr: %s, port: %s\n", host, port)
	ips, err := net.LookupIP(host)
	if err != nil {
		fmt.Printf("Error resolving host: %s\n", err)
		os.Exit(1)
	}

	ip := ips[0]
	fmt.Println("ip", ip)

	if !isServer {
		cfg.Mode = "client"
		cfg.RemoteAddr = ip.String()
		cfg.RemotePort = port

	} else {
		cfg.Mode = "server"
		cfg.LocalAddr = ip.String()
		cfg.LocalPort = port
	}

	tun, err := network.SetUpTUN(cfg)
	if err != nil {
		fmt.Printf("Error creating tun interface: %s\n", err)
		os.Exit(1)
	}

	var t transport.Transport = nil
	switch cfg.Protocol {
	case "udp":
		fmt.Println("Using UDP Transport.")
		t = transport.NewUdpTransport(cfg)
	case "tcp":
		fmt.Println("Using TCP Transport.")
		t = transport.NewTcpTransport(cfg)
	default:
		fmt.Printf("Unknown Protocol: %s\n", cfg.Protocol)
		os.Exit(1)
	}
	t.Init(cfg)
	if isServer {
		for {
			err = t.WaitConnection(cfg, tun, protocol.ProcessClient)
			if err != nil {
				fmt.Println(err)
				break
			}
			t.Close()
		}
	} else {
		protocol.ProcessServer(t, t.GetClientConn(), tun)
	}
	t.Close()
}
