package protocol

import (
	"context"
	"log"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/sem-hub/snake-net/internal/clients"
	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/network"
	"github.com/sem-hub/snake-net/internal/network/transport"
)

var logger *slog.Logger
var cfg *configs.RuntimeConfig = nil

func ResolveAndProcess(ctx context.Context, t transport.Transport) {
	logger = configs.InitLogger("protocol")
	cfg = configs.GetConfig()

	host := ""
	port := 0
	if cfg.Mode == "server" {
		host = cfg.LocalAddr
		port = int(cfg.LocalPort)
		if port == 0 {
			log.Fatal("Local Port is mandatory for server")
		}
	} else {
		host = cfg.RemoteAddr
		port = int(cfg.RemotePort)
		if host == "" || port == 0 {
			log.Fatal("Remote Address and Port are mandatory for client")
		}
	}

	logger.Debug("URI", "Protocol", cfg.Protocol, "address", host, "port", port)

	if strings.HasPrefix((host), "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	ip := net.ParseIP(host)
	var ips []net.IP
	if ip == nil {
		logger.Debug("Resolving.")
		var err error
		ips, err = net.LookupIP(host)
		if err != nil {
			log.Fatalf("Error resolving host: %s", err)
			os.Exit(1)
		}
		logger.Info("Resolving", "host", host, "ips", ips)
	} else {
		ips = []net.IP{ip}
	}

	if cfg.Mode == "server" {
		lAddrPort := netip.AddrPortFrom(netip.MustParseAddr(cfg.LocalAddr).Unmap(), uint16(cfg.LocalPort))

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
			log.Fatalf("Error creating tun interface: %s", err)
		}
		clients.SetTunInterface(tunIf)

		logger.Info("Start server", "addr", cfg.LocalAddr, "port", cfg.LocalPort)
		<-ctx.Done()
	} else {
		attempts := 0
		for tryNo := 0; tryNo < len(ips); tryNo++ {
			rAddrPort := netip.AddrPortFrom(netip.MustParseAddr(ips[tryNo].String()).Unmap(), uint16(port))
			lAddrPort := netip.AddrPortFrom(netip.MustParseAddr(cfg.LocalAddr).Unmap(), uint16(cfg.LocalPort))

			if rAddrPort.Addr().Is6() {
				cfg.RemoteAddr = "[" + ips[tryNo].String() + "]"
			} else {
				cfg.RemoteAddr = ips[tryNo].String()
			}

			// Set up transport. No callback for client mode
			err := t.Init("client", rAddrPort, lAddrPort, nil)
			if err != nil {
				logger.Error("Transport init error", "error", err)
				attempts++
				// MaxAttempts == 0 means infinite attempts
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

			logger.Info("Connected to", "addr", cfg.RemoteAddr, "port", cfg.RemotePort)

			// Run client in a goroutine so we can listen for context cancellation
			v := make(chan bool)
			go func() {
				err := ProcessServer(t, rAddrPort)
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
}
