package protocol

import (
	"context"
	"crypto/sha256"
	"math/rand"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/sem-hub/snake-net/internal/clients"
	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/network"
	"github.com/sem-hub/snake-net/internal/network/transport"
)

func ResolveAndProcess(ctx context.Context) {
	logger := configs.InitLogger("protocol")
	cfg := configs.GetConfig()
	logger.Debug("Crypto engine: " + cfg.Engine)
	logger.Debug("Signature engine: " + cfg.SignEngine)

	host := ""
	port := 0
	if cfg.IsServer {
		host = cfg.LocalAddr
		port = int(cfg.LocalPort)
		// If port is 0, we will choose a random port and open it in firewall.
		if port == 0 {
			port = rand.Intn(65535-1024) + 1024
			cfg.LocalPort = uint16(port)
			logger.Info("Using random port", "port", port)
		}
	} else {
		host = cfg.RemoteAddr
		port = int(cfg.RemotePort)
		if host == "" {
			logger.Fatal("Remote Address is mandatory for client")
		}
	}

	var t transport.Transport
	// Check if transport is available
	if !transport.IsTransportAvailable(cfg.Protocol) {
		logger.Fatal("Transport " + cfg.Protocol + " is not available. Available transports: " +
			strings.Join(transport.GetAvailableTransports(), ", "))
	}

	logger.Info("Using transport: " + strings.ToUpper(cfg.Protocol))

	var err error
	// Create transport based on protocol
	if cfg.Protocol == "kcp" {
		// KCP requires a key
		sum256 := sha256.Sum256([]byte(cfg.Secret))
		kcpKey := sum256[:]
		t, err = transport.NewTransportByName(cfg.Protocol, kcpKey)
	} else {
		t, err = transport.NewTransportByName(cfg.Protocol)
	}

	if err != nil {
		logger.Fatal("Failed to create transport: " + err.Error())
	}

	if cfg.IsServer && !t.IsEncrypted() && (cfg.Engine == "") {
		logger.Fatal("Transport is not encrypted and no cipher/signature engine is specified.")
	}

	logger.Debug("URI", "Protocol", cfg.Protocol, "address", host, "port", port)

	if strings.HasPrefix((host), "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	// Check if we have plain IP or if we need to resolve
	ip := net.ParseIP(host)
	var ips []net.IP
	if ip == nil {
		logger.Debug("Start resolving", "host", host)
		var err error
		ips, err = net.LookupIP(host)
		if err != nil {
			logger.Fatal("Error resolving host", "error", err)
		}
		logger.Info("Resolved", "host", host, "ips", ips)
	} else {
		ips = []net.IP{ip}
	}

	if cfg.IsServer {
		logger.Info("Starting ICMP listener for port requests")
		network.StartICMPListen(cfg.Secret)

		lAddrPort := netip.AddrPortFrom(netip.MustParseAddr(cfg.LocalAddr).Unmap(), uint16(cfg.LocalPort))

		// Open Firewall port for incoming connections
		err = network.OpenFirewallPort(lAddrPort.Port(), t.WireProtocol())
		if err != nil {
			logger.Error("Error opening firewall port", "error", err)
			return
		}

		if lAddrPort.Addr().Is6() {
			cfg.LocalAddr = "[" + lAddrPort.Addr().String() + "]"
		}

		// Set up transport with callback for new clients
		err := t.Init("server", netip.AddrPort{}, lAddrPort, ProcessNewClient)
		if err != nil {
			logger.Error("Transport init error", "error", err)
			return
		}

		// Set up TUN interface
		logger.Info("TUN Addresses", "addrs", cfg.TunAddrs)

		tunIf, err := network.NewTUN(cfg.TunName, cfg.TunAddrs, cfg.TunMTU)
		if err != nil {
			logger.Fatal("Error creating tun interface", "error", err)
		}
		clients.SetTunInterface(tunIf)

		logger.Info("Start server", "addr", cfg.LocalAddr, "port", cfg.LocalPort)

		if cfg.Socks5Enabled {
			go func() {
				network.RunSOCKS5(ctx, cfg.TunAddrs, int(cfg.Socks5Port), cfg.Socks5Username, cfg.Socks5Password)
			}()
		}
		// Wait for context cancellation (Ctrl-C)
		<-ctx.Done()

		if cfg.IsServer {
			err = network.CloseFirewallPort(lAddrPort.Port(), t.WireProtocol())
			if err != nil {
				logger.Error("Error closing firewall port", "error", err)
			}
		}
	} else {
		// For client, we will traverse to each resolved server IP until we succeed.
		attempts := 0
		for tryNo := 0; tryNo < len(ips); tryNo++ {
			if ips[tryNo].To4() != nil {
				if cfg.PreferIPv6 && !cfg.PreferIPv4 {
					logger.Debug("Skipping IPv4 address due to prefer_ipv4=false", "ip", ips[tryNo].String())
					continue
				}
			} else {
				if cfg.PreferIPv4 && !cfg.PreferIPv6 {
					logger.Debug("Skipping IPv6 address due to prefer_ipv6=false", "ip", ips[tryNo].String())
					continue
				}
			}
			if port == 0 {
				logger.Info("Asking port from server via ICMP", "peer", ips[tryNo].String())
				port = network.GetICMPPort(net.IPAddr{IP: ips[tryNo]}, cfg.Secret)
				if port == 0 {
					logger.Fatal("Failed to get port from server via ICMP, will retry", "peer", ips[tryNo].String())
				}
				logger.Info("Got port from server", "port", port)
			}

			rAddrPort := netip.AddrPortFrom(netip.MustParseAddr(ips[tryNo].String()).Unmap(), uint16(port))
			lAddrPort := netip.AddrPortFrom(netip.MustParseAddr(cfg.LocalAddr).Unmap(), uint16(cfg.LocalPort))

			if rAddrPort.Addr().Is6() {
				cfg.RemoteAddr = "[" + ips[tryNo].String() + "]"
			} else {
				cfg.RemoteAddr = ips[tryNo].String()
			}

			// Set up transport. No callback for client mode.
			err := t.Init("client", rAddrPort, lAddrPort, nil)
			if err != nil {
				logger.Error("Transport init error", "error", err)
				attempts++
				// MaxAttempts == 0 means infinite attempts.
				if configs.GetConfig().Attempts > 0 &&
					attempts >= configs.GetConfig().Attempts {
					logger.Info("Max attempts reached, give up")
					return
				}
				retryDelay := configs.GetConfig().RetryDelay
				logger.Info("Retrying in", "seconds", retryDelay)

				// Make retry delay interruptible so we can stop promptly on ctx cancellation
				select {
				case <-ctx.Done():
					logger.Info("Context cancelled during retry delay")
					return
				case <-time.After(time.Duration(retryDelay) * time.Second):
					// continue retrying
				}

				if tryNo == len(ips)-1 {
					tryNo = -1
				}
				continue
			}

			logger.Debug("Connected to", "server", rAddrPort.String())

			// Run client in a goroutine so we can listen for context cancellation
			v := make(chan bool)
			go func() {
				err := ProcessServer(ctx, t, rAddrPort)
				if err != nil {
					logger.Error("ProcessServer error", "error", err)
					v <- false
					return
				}
				v <- true
			}()

			// Wait for context cancellation (Ctrl-C) or normal exit
			select {
			case <-ctx.Done():
				logger.Info("Shutting down client due to context cancellation")
			case b := <-v:
				if !b {
					logger.Info("ProcessServer exited with error")
					// Try again after delay
					attempts++
					// MaxAttempts == 0 means infinite attempts
					if configs.GetConfig().Attempts > 0 &&
						attempts >= configs.GetConfig().Attempts {
						logger.Info("Max attempts reached, give up")
						return
					}
					retryDelay := configs.GetConfig().RetryDelay
					logger.Info("Retrying in", "seconds", retryDelay)
					time.Sleep(time.Duration(retryDelay) * time.Second)
					if tryNo == len(ips)-1 {
						tryNo = -1
					}
					continue
				} else {
					logger.Info("ProcessServer exited normally")
				}
			}
			logger.Info("ProcessServer exited")
		}
	}

	// Clean up transport
	if t != nil {
		t.Close()
	}
}
