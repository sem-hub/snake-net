package transport

import (
	"log/slog"
	"net"
)

type Message = []byte

type Transport interface {
	// mode, remoteAddr, remotePort, localAddr, localPort and Callback for new connection processing
	Init(string, string, string, string, string, func(Transport, net.Conn, net.Addr)) error
	Send(net.Addr, net.Conn, *Message) error
	Receive(net.Conn, net.Addr) (Message, int, net.Addr, error)
	Close() error
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
