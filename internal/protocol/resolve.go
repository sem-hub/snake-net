package protocol

import (
	"log"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/network/transport"
)

var logger *slog.Logger
var cfg *configs.RuntimeConfig = nil

func NewLogger(level slog.Level) *slog.Logger {
	logger := slog.New(
		slog.NewTextHandler(
			os.Stderr,
			&slog.HandlerOptions{
				Level: level,
			},
		),
	)
	slog.SetDefault(logger)
	return logger
}

func ResolveAndProcess(t transport.Transport, host string, port uint32) {
	logger = NewLogger(slog.LevelDebug)
	cfg = configs.GetConfig()

	if host == "" {
		if cfg.Mode == "server" {
			host = "0.0.0.0"
		} else {
			log.Fatal("Server Address is mandatory for client")
		}
	}
	logger.Debug("URI", "Protocol", cfg.Protocol, "Peer", host, "port", port)

	if cfg.Mode == "server" {
		cfg.LocalPort = port

	} else {
		cfg.RemotePort = port
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
	logger.Debug("", "ip", ip, "mode", cfg.Mode)

	if cfg.Mode == "server" {
		if len(ip) == 16 {
			cfg.LocalAddr = "[" + ip.String() + "]"
		} else {
			cfg.LocalAddr = ip.String()
		}

		err := t.Init("server", cfg.RemoteAddr+":"+strconv.Itoa(int(cfg.RemotePort)),
			cfg.LocalAddr+":"+strconv.Itoa(int(cfg.LocalPort)), ProcessNewClient)
		if err != nil {
			log.Fatalf("Transport init error %s", err)
		}

		logger.Info("Start server", "addr", cfg.LocalAddr, "port", cfg.LocalPort)
	} else {
		if len(ip) == 16 {
			cfg.RemoteAddr = "[" + ip.String() + "]"
		} else {
			cfg.RemoteAddr = ip.String()
		}

		// No callback for client mode
		rAddrPortStr := cfg.RemoteAddr + ":" + strconv.Itoa(int(cfg.RemotePort))
		lAddrPortStr := cfg.LocalAddr + ":" + strconv.Itoa(int(cfg.LocalPort))
		err := t.Init("client", rAddrPortStr, lAddrPortStr, nil)
		if err != nil {
			log.Fatalf("Transport init error %s", err)
		}

		logger.Info("Connected to", "addr", cfg.RemoteAddr, "port", cfg.RemotePort)

		ProcessServer(t, netip.MustParseAddrPort(rAddrPortStr))
	}
	forever := make(chan bool)
	<-forever

}
