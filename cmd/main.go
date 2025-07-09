package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/protocol"
	"github.com/sem-hub/snake-net/internal/transport"
)

var (
	cfg      *configs.Config
	isServer bool
	isIPv6   bool
)

func init() {
	cfg = configs.NewConfig()
	flag.BoolVar(&isServer, "server", false, "Run as server.")
	flag.BoolVar(&isIPv6, "6", false, "Use IPv6.")
}
func main() {
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	addr := flag.Arg(0)
	if strings.Count(addr, ":") < 2 {
		fmt.Printf("Invalid Address: %s. proto:host:port format expected\n", addr)
		os.Exit(1)
	}

	cfg.Protocol = strings.ToLower(strings.Split(addr, ":")[0])
	fmt.Printf("Protocol: %s\n", cfg.Protocol)
	host, port, err := net.SplitHostPort(addr[len(cfg.Protocol)+1:])
	if err != nil {
		fmt.Printf("Error parsing address: %s\n", err)
		os.Exit(1)
	}

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
