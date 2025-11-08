package transport

import (
	"log/slog"
	"net/netip"
)

type Message = []byte

type Transport interface {
	// Init data, connect to server or listen for clients (depend on "mode")
	// Arguments: mode (client|server), remoteAddr:remotePort, localAddr:localPort
	//            and Callback for new connection processing
	Init(string, string, string, func(Transport, netip.AddrPort)) error
	// Send/Receive data
	Send(netip.AddrPort, *Message) error
	Receive(netip.AddrPort) (Message, int, error)
	Close() error                     // Close main (listening) connection
	CloseClient(netip.AddrPort) error // Close client connection by address
	// Return protocol name
	GetName() string
	// Return protocol type (stream/datagram)
	GetType() string
	// Does the protocol support Crypt on low-level?
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
