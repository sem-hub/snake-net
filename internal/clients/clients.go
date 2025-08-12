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
		conn:    conn,
		state:   Connected,
		secrets: nil,
	})
}

func AddSecretsToClient(address net.Addr, s *crypt.Secrets) {
	lock.Lock()
	defer lock.Unlock()
	for i, _ := range clients {
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

func SendAllExceptOne(data []byte, address net.Addr) {
	lock.Lock()
	clientsCopy := make([]client, len(clients))
	copy(clientsCopy, clients)
	lock.Unlock()

	configs.GetLogger().Debug("SendAllExceptOne", "address", address, "len", len(data))
	for _, c := range clientsCopy {
		if address == nil || c.address.String() != address.String() {
			if c.secrets != nil {
				go func(cl client) {
					err := cl.secrets.Write(&data)
					if err != nil {
						configs.GetLogger().Error("SendAllExceptOne", "error", err)
					}
				}(c)
			}
		}
	}
}
