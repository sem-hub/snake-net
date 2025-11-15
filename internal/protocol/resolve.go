package protocol

import (
	"context"
	"log"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/sem-hub/snake-net/internal/clients"
	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/network"
	"github.com/sem-hub/snake-net/internal/network/transport"
)

var logger *slog.Logger
var cfg *configs.RuntimeConfig = nil

func ResolveAndProcess(ctx context.Context, t transport.Transport, host string, port uint16) {
	logger = configs.InitLogger("protocol")
	cfg = configs.GetConfig()

	// XXX
	if host == "" {
		if cfg.Mode == "server" {
			host = "0.0.0.0"
			cfg.LocalAddr = host
		} else {
			log.Fatal("Server Address is mandatory for client")
		}
	}
	logger.Debug("URI", "Protocol", cfg.Protocol, "Peer", host, "port", port)

	if cfg.Mode == "server" {
		cfg.LocalPort = port
	} else {
		cfg.RemotePort = port
		if cfg.LocalAddr == "" {
			cfg.LocalAddr = "0.0.0.0"
		}
	}

	if strings.HasPrefix((host), "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	ip := net.ParseIP(host)
	if ip == nil {
		logger.Debug("Resolving.")
		ips, err := net.LookupIP(host)
		if err != nil {
			log.Fatalf("Error resolving host: %s", err)
			os.Exit(1)
		}

		ip = ips[0]
	}

	rAddrPort := netip.AddrPortFrom(netip.MustParseAddr(ip.String()).Unmap(), uint16(port))
	lAddrPort := netip.AddrPortFrom(netip.MustParseAddr(cfg.LocalAddr).Unmap(), uint16(cfg.LocalPort))
	logger.Debug("", "ip", ip, "mode", cfg.Mode)
	if cfg.Mode == "server" {
		if len(ip) == 16 {
			cfg.LocalAddr = "[" + ip.String() + "]"
		} else {
			cfg.LocalAddr = ip.String()
		}

		// Set up transport with callback for new clients
		err := t.Init("server", rAddrPort, lAddrPort, ProcessNewClient)
		if err != nil {
			log.Fatalf("Transport init error %s", err)
		}

		// Set up TUN interface
		logger.Info("TUN Addresses", "addrs", cfg.TunAddrs)

		tunIf, err := network.NewTUN(cfg.TunName, cfg.TunAddrs, cfg.TunMTU)
		if err != nil {
			log.Fatalf("Error creating tun interface: %s", err)
		}
		clients.SetTunInterface(tunIf)

		logger.Info("Start server", "addr", cfg.LocalAddr, "port", cfg.LocalPort)
		<-ctx.Done()
	} else {
		if len(ip) == 16 {
			cfg.RemoteAddr = "[" + ip.String() + "]"
		} else {
			cfg.RemoteAddr = ip.String()
		}

		// Set up transport. No callback for client mode
		err := t.Init("client", rAddrPort, lAddrPort, nil)
		if err != nil {
			log.Fatalf("Transport init error %s", err)
		}

		logger.Info("Connected to", "addr", cfg.RemoteAddr, "port", cfg.RemotePort)

		// Run client in a goroutine so we can listen for context cancellation
		v := make(chan struct{})
		go func() {
			err := ProcessServer(t, rAddrPort)
			if err != nil {
				logger.Error("ProcessServer error", "error", err)
			}
			v <- struct{}{}
		}()

		// Wait for context cancellation (Ctrl-C) or normal exit
		select {
		case <-ctx.Done():
		case <-v:
		}
		logger.Info("ProcessServer exited")
	}
}
