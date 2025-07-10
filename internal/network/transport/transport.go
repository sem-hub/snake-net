package transport

import (
	"net"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/songgao/water"
)

type Message = []byte

type Transport interface {
	Init(*configs.Config) error
	WaitConnection(*configs.Config, *water.Interface, func(Transport, net.Conn, *water.Interface)) error
	Send(net.Conn, *Message) error
	Receive(net.Conn) (*Message, int, error)
	Close() error
	GetClientConn() net.Conn
}

type TransportData struct {
	PeerAddr string
	BindAddr string
}

func NewTransport(c *configs.Config) *TransportData {
	return &TransportData{"", ""}
}
