package clients

import (
	"net"

	"github.com/sem-hub/snake-net/internal/configs"
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
}

var (
	clients = []client{}
)

func AddClient(conn net.Conn, address net.Addr) {
	logging := configs.GetLogger()
	logging.Debug("AddClient", "address", address)
	clients = append(clients, client{
		address: address,
		conn:    conn,
		state:   Connected,
	})
}

func RemoveClient(address net.Addr) {
	for i, c := range clients {
		if c.address.String() == address.String() {
			clients = append(clients[:i], clients[i+1:]...)
		}
	}
}

func GetClientState(address net.Addr) State {
	for _, c := range clients {
		if c.address.String() == address.String() {
			return c.state
		}
	}
	return NotFound
}

func SetClientState(address net.Addr, state State) {
	for i, c := range clients {
		if c.address.String() == address.String() {
			clients[i].state = state
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
