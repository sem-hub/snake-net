package network

import (
	"context"
	"fmt"
	"net"

	"github.com/sem-hub/snake-net/internal/configs"
	socks5 "github.com/things-go/go-socks5"
)

func RunSOCKS5(ctx context.Context, port int, username, password string) {
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

	addr := fmt.Sprintf(":%d", port)
	logger.Info("SOCKS5 server started", "port", port)

	// Create listener
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Error("Failed to create listener", "error", err)
		return
	}

	// Start the server in goroutine
	go func() {
		if err := server.Serve(listener); err != nil && err != net.ErrClosed {
			logger.Error("Error running SOCKS5 server", "error", err)
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()
	logger.Info("Shutting down SOCKS5 server")

	// Close listener to stop accepting connections
	listener.Close()
}
