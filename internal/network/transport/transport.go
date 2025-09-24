package transport

import (
	"log/slog"
	"net"
	"net/netip"
)

type Message = []byte

type Transport interface {
	// mode, remoteAddr, remotePort, localAddr, localPort and Callback for new connection processing
	Init(string, string, string, string, string, func(Transport, netip.AddrPort)) error
	Send(netip.AddrPort, *Message) error
	Receive(netip.AddrPort) (Message, int, error)
	Close() error                     // Close main (listening) connection
	CloseClient(netip.AddrPort) error // Close client connection by address
	GetMainConn() net.Conn
	GetName() string
	GetType() string
	IsEncrypted() bool
}

type TransportData struct {
	Logger *slog.Logger
}

const NETBUFSIZE = 9000

var logger *slog.Logger

func NewTransport(loggerHandler *slog.Logger) *TransportData {
	logger = loggerHandler
	return &TransportData{
		Logger: logger,
	}
}
