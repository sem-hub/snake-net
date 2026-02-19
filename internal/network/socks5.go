package network

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/utils"
	socks5 "github.com/things-go/go-socks5"
)

func RunSOCKS5(ctx context.Context, cidrs []utils.Cidr, port int, username, password string) {
	logger := configs.InitLogger("socks5")
	requireAuth := username != ""

	if requireAuth {
		logger.Info("SOCKS5 authentication enabled", "username", username)
	} else {
		logger.Info("SOCKS5 authentication disabled")
	}

	// Configure SOCKS5 server with custom options
	var server *socks5.Server

	if requireAuth {
		// Create authenticator with username/password
		creds := socks5.StaticCredentials{
			username: password,
		}
		authenticator := socks5.UserPassAuthenticator{Credentials: creds}

		server = socks5.NewServer(
			socks5.WithAuthMethods([]socks5.Authenticator{authenticator}),
		)
	} else {
		// No authentication
		server = socks5.NewServer()
	}

	listeners := make([]net.Listener, 0)
	for _, cidr := range cidrs {
		var addr *net.TCPAddr
		family := "tcp4"
		if !cidr.IP.Is4() {
			family = "tcp6"
		}
		addr = &net.TCPAddr{
			IP:   cidr.IP.AsSlice(),
			Port: port,
		}
		logger.Info("SOCKS5 server started", "address", addr.String())

		// Create listener
		listener, err := net.ListenTCP(family, addr)
		if err != nil {
			logger.Error("Failed to create listener", "error", err)
			return
		}

		// Start the server in goroutine
		go func() {
			if err := server.Serve(listener); err != nil && !errors.Is(err, net.ErrClosed) {
				logger.Error("Error running SOCKS5 server", "error", err)
			}
		}()
		listeners = append(listeners, listener)
		time.Sleep(100 * time.Millisecond)
	}
	// Wait for context cancellation
	<-ctx.Done()
	logger.Info("Shutting down SOCKS5 server")

	// Close listener to stop accepting connections
	for _, listener := range listeners {
		listener.Close()
	}
}
