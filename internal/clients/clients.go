package clients

import (
	"net"
	"sync"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/crypt"
)

type State int

const (
	NotFound State = iota
	Connected
	Authenticated
	Ready
	HasData
)

type client struct {
	address net.Addr
	tunAddr net.Addr
	conn    net.Conn
	state   State
	secrets *crypt.Secrets
}

var (
	clients = []client{}
	lock    sync.Mutex
)

func AddClient(conn net.Conn, address net.Addr) {
	lock.Lock()
	defer lock.Unlock()

	logging := configs.GetLogger()
	logging.Debug("AddClient", "address", address)
	clients = append(clients, client{
		address: address,
		tunAddr: nil,
		conn:    conn,
		state:   Connected,
		secrets: nil,
	})
}

func AddSecretsToClient(address net.Addr, s *crypt.Secrets) {
	lock.Lock()
	defer lock.Unlock()
	for i := range clients {
		if clients[i].address.String() == address.String() {
			clients[i].secrets = new(crypt.Secrets)
			clients[i].secrets = s
			break
		}
	}
}

func RemoveClient(address net.Addr) {
	lock.Lock()
	defer lock.Unlock()
	for i, c := range clients {
		if c.address.String() == address.String() {
			clients = append(clients[:i], clients[i+1:]...)
			break
		}
	}
}

func GetClientState(address net.Addr) State {
	lock.Lock()
	defer lock.Unlock()

	for _, c := range clients {
		if c.address.String() == address.String() {
			return c.state
		}
	}
	return NotFound
}

func SetClientState(address net.Addr, state State) {
	lock.Lock()
	defer lock.Unlock()

	for i, c := range clients {
		if c.address.String() == address.String() {
			clients[i].state = state
			break
		}
	}
}

func GetClientCount() int {
	if clients == nil {
		return 0
	} else {
		return len(clients)
	}
}

func getSenderIP(packet []byte) net.Addr {
	if len(packet) < 1 {
		return nil
	}
	version := packet[0] >> 4 // First 4 bits
	if version == 4 {
		return &net.IPAddr{IP: packet[16:20]} // IPv4 addresse in bytes 16-19
	}
	return nil
}

func SendAllExceptSender(data []byte) {
	lock.Lock()
	clientsCopy := make([]client, len(clients))
	copy(clientsCopy, clients)
	lock.Unlock()
	logging := configs.GetLogger()

	address := getSenderIP(data)
	if address == nil {
		logging.Debug("SendAllExceptSender: no sender IP found")
		return
	}
	logging.Debug("SendAllExceptSender", "address", address, "len", len(data))
	for _, c := range clientsCopy {
		logging.Debug("SendAllExceptSender", "address", address, "client", c.address)
		if c.address.String() != address.String() {
			if c.secrets != nil {
				go func(cl client) {
					err := cl.secrets.Write(&data)
					if err != nil {
						logging.Error("SendAllExceptSender write", "error", err)
					}
				}(c)
			}
		}
	}
}
