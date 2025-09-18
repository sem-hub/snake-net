package transport

import (
	"net"

	"github.com/sem-hub/snake-net/internal/configs"
)

type Message = []byte

type Transport interface {
	// Callback for new connection processing
	Init(*configs.Config, func(Transport, net.Conn, net.Addr)) error
	Send(net.Addr, net.Conn, *Message) error
	Receive(net.Conn, net.Addr) (Message, int, net.Addr, error)
	Close() error
	GetMainConn() net.Conn
	GetName() string
}

type TransportData struct {
}

func NewTransport(c *configs.Config) *TransportData {
	return &TransportData{}
}
