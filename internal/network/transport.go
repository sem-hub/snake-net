package network

import (
	"net"

	"github.com/sem-hub/snake-net/internal/configs"
)

type Message = []byte

type Transport interface {
	Init(*configs.Config) error
	WaitConnection(*configs.Config, func(Transport, net.Conn)) error
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
