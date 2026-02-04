package transport

import (
	"net/netip"

	"github.com/sem-hub/snake-net/internal/configs"
)

type Message = []byte

type Transport interface {
	// Init data, connect to server or listen for clients (depend on "mode")
	// Arguments: mode (client|server), remoteAddr:remotePort, localAddr:localPort
	//            and Callback for new connection processing
	Init(string, netip.AddrPort, netip.AddrPort, func(Transport, netip.AddrPort)) error
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
	logger *configs.ColorLogger
}

const NETBUFSIZE = 9000

func NewTransport() *TransportData {
	t := &TransportData{}
	t.logger = configs.InitLogger("transport")
	return t
}
