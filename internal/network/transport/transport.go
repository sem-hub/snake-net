package transport

import (
	"errors"
	"net/netip"
	"sync"

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
	WireProtocol() string // Return underlying protocol (TCP/UDP)
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

// Transport factory
type TransportConstructor func(args ...interface{}) (Transport, error)

var (
	transportRegistry = make(map[string]TransportConstructor)
	registryMutex     sync.RWMutex
)

// RegisterTransport registers a transport constructor under a given name
func RegisterTransport(name string, constructor TransportConstructor) {
	registryMutex.Lock()
	defer registryMutex.Unlock()
	transportRegistry[name] = constructor
}

// NewTransportByName creates a new transport instance by name
func NewTransportByName(name string, args ...interface{}) (Transport, error) {
	registryMutex.RLock()
	constructor, exists := transportRegistry[name]
	registryMutex.RUnlock()

	if !exists {
		return nil, errors.New("transport " + name + " is not available")
	}

	return constructor(args...)
}

// GetAvailableTransports returns a list of all registered transport names
func GetAvailableTransports() []string {
	registryMutex.RLock()
	defer registryMutex.RUnlock()

	names := make([]string, 0, len(transportRegistry))
	for name := range transportRegistry {
		names = append(names, name)
	}
	return names
}

// IsTransportAvailable checks if a transport is registered
func IsTransportAvailable(name string) bool {
	registryMutex.RLock()
	defer registryMutex.RUnlock()
	_, exists := transportRegistry[name]
	return exists
}
