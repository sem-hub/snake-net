package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/network"
	"github.com/sem-hub/snake-net/internal/protocol"
)

var (
	cfg      *configs.Config
	isServer bool
	tunAddr  string
)

func init() {
	cfg = configs.NewConfig()
	flag.BoolVar(&isServer, "server", false, "Run as server.")
	flag.StringVar(&tunAddr, "tun", "", "Address for Tun interface.")
}
func main() {
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	addr := strings.ToLower(flag.Arg(0))

	re := regexp.MustCompile(`([a-z]+)://((?:[0-9]{1,3}[\.]){3}[0-9]{1,3}|\[(?:[0-9a-f]{0,4}:){1,7}[0-9a-f]{0,4}\]):([0-9]+)`)
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

	if !isServer {
		cfg.Mode = "client"
		cfg.RemoteAddr = ip.String()
		cfg.RemotePort = port

	} else {
		cfg.Mode = "server"
		cfg.LocalAddr = ip.String()
		cfg.LocalPort = port
	}

	if err := network.SetUpTUN(cfg); err != nil {
		fmt.Printf("Error creating tun interface: %s\n", err)
		os.Exit(1)
	}

	var t network.Transport = nil
	switch cfg.Protocol {
	case "udp":
		fmt.Println("Using UDP Transport.")
		t = network.NewUdpTransport(cfg)
	case "tcp":
		fmt.Println("Using TCP Transport.")
		t = network.NewTcpTransport(cfg)
	default:
		fmt.Printf("Unknown Protocol: %s\n", cfg.Protocol)
		os.Exit(1)
	}
	t.Init(cfg)
	if isServer {
		for {
			err = t.WaitConnection(cfg, protocol.ProcessClient)
			if err != nil {
				fmt.Println(err)
				break
			}
			t.Close()
		}
	} else {
		protocol.ProcessServer(t, t.GetClientConn())
	}
	t.Close()
}
