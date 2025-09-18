package transport

import (
	"log/slog"
	"net"
)

type Message = []byte

type Transport interface {
	// Callback for new connection processing
	Init(func(Transport, net.Conn, net.Addr)) error
	Send(net.Addr, net.Conn, *Message) error
	Receive(net.Conn, net.Addr) (Message, int, net.Addr, error)
	Close() error
	GetMainConn() net.Conn
	GetName() string
}

type TransportData struct {
	Logger *slog.Logger
}

var logger *slog.Logger

func NewTransport(loggerHandler *slog.Logger) *TransportData {
	logger = loggerHandler
	return &TransportData{
		Logger: logger,
	}
}
