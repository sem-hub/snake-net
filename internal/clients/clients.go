package clients

import (
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/crypt"

	//lint:ignore ST1001 reason: it's safer to use . import here to avoid name conflicts
	. "github.com/sem-hub/snake-net/internal/interfaces"
	"github.com/sem-hub/snake-net/internal/network/transport"
	"github.com/sem-hub/snake-net/internal/utils"
)

type State int

const (
	BUFSIZE        = 524288 // 512 KB
	SENTBUFFERSIZE = 200    // keep 200 packets after sending
)

const (
	NotFound State = iota
	Connected
	Authenticated
	Ready
	HasData
)

type Client struct {
	logger         *slog.Logger
	address        netip.AddrPort
	tunAddrs       []utils.Cidr
	t              transport.Transport
	state          State
	secrets        *crypt.Secrets
	buf            []byte
	bufLock        *sync.Mutex
	bufSignal      *sync.Cond
	bufSize        int
	bufOffset      int
	seqIn          uint32 // always read/write under bufLock
	seqOut         *atomic.Uint32
	oooPackets     int
	ooopTimer      *time.Timer
	reaskedPackets int
	sentBuffer     *utils.CircularBuffer
	orderSendLock  *sync.Mutex
	closed         bool
	id             string
	pinger         *PingerClient
}

var (
	// holds client pointers. Keys are both client IPs and tunnel IPs (points to the same client)
	clients      = map[netip.AddrPort]*Client{}
	clientsLock  sync.RWMutex
	tunAddrs     = map[netip.Addr]*Client{}
	tunAddrsLock sync.RWMutex
	tunIf        TunInterface
)

func SetTunInterface(tun TunInterface) {
	tunIf = tun
}

func (c *Client) CreatePinger() {
	c.pinger = NewPingerForClient(c)
}

func (c *Client) GetSecrets() *crypt.Secrets {
	return c.secrets
}

func (c *Client) GetClientAddr() netip.AddrPort {
	return c.address
}

func (c *Client) GetTunAddrs() []utils.Cidr {
	return c.tunAddrs
}

func (c *Client) IsClosed() bool {
	return c.closed
}

func NewClient(address netip.AddrPort, t transport.Transport) *Client {
	logger := configs.InitLogger("clients")
	logger.Debug("AddClient", "address", address)
	client := Client{
		logger:         logger,
		address:        address,
		tunAddrs:       nil,
		t:              t,
		state:          Connected,
		secrets:        nil,
		buf:            make([]byte, BUFSIZE),
		bufLock:        &sync.Mutex{},
		bufSize:        0,
		bufOffset:      0,
		seqIn:          1,
		seqOut:         &atomic.Uint32{},
		oooPackets:     0,
		reaskedPackets: 0,
		sentBuffer:     utils.NewCircularBuffer(SENTBUFFERSIZE),
		orderSendLock:  &sync.Mutex{},
		closed:         false,
		id:             "",
		pinger:         nil,
		ooopTimer:      nil,
	}
	client.bufSignal = sync.NewCond(client.bufLock)
	client.seqOut.Store(1)

	if len(clients) != 0 && FindClient(address) != nil {
		logger.Info("Client already exists", "address", address)
	} else {
		clientsLock.Lock()
		clients[address] = &client
		clientsLock.Unlock()
		logger.Debug("Client added", "address", address.String())
	}
	return &client
}

func (c *Client) AddTunAddressesToClient(cidrs []utils.Cidr) {
	c.tunAddrs = append(c.tunAddrs, cidrs...)
	for _, cidr := range cidrs {
		tunAddrsLock.Lock()
		tunAddrs[cidr.IP] = c
		tunAddrsLock.Unlock()
		c.logger.Info("AddTunAddressesToClient", "address", c.address.String(), "tunAddr", cidr)
	}
}

func (c *Client) AddSecretsToClient(s *crypt.Secrets) {
	c.secrets = s
}

// Closes the client connection and removes it from the clients map
func RemoveClient(address netip.AddrPort) {
	client := FindClient(address)
	if client != nil {
		client.Close() // Close connection here
		// Remvove all tun addresses
		for _, cidr := range client.tunAddrs {
			tunAddrsLock.Lock()
			delete(tunAddrs, cidr.IP)
			tunAddrsLock.Unlock()
			client.logger.Info("RemoveClient tunAddr", "tunAddr", cidr.String())
		}
		clientsLock.Lock()
		delete(clients, address)
		clientsLock.Unlock()
		client.logger.Info("RemoveClient", "address", address.String())
	}
	if GetClientsCount() == 0 {
		if configs.GetConfig().Mode != "server" && tunIf != nil {
			tunIf.Close()
		}
		// Close transport
		if client != nil {
			client.t.Close()
		}
	}
}

func FindClient(address netip.AddrPort) *Client {
	clientsLock.RLock()
	defer clientsLock.RUnlock()
	if c, ok := clients[address]; ok {
		return c
	}
	return nil
}

func FindClientTunAddr(addr netip.Addr) *Client {
	tunAddrsLock.RLock()
	defer tunAddrsLock.RUnlock()
	if c, ok := tunAddrs[addr]; ok {
		return c
	}
	return nil
}

func (c *Client) GetClientState() State {
	return c.state
}

func (c *Client) SetClientState(state State) {
	c.state = state
	c.logger.Debug("SetClientState", "address", c.address.String(), "state", state)
}

func (c *Client) SetClientId(id string) {
	c.id = id
	c.logger.Info("SetClientId", "address", c.address.String(), "id", id)
}

func GetClientsCount() int {
	clientsLock.RLock()
	defer clientsLock.RUnlock()

	if clients == nil {
		return 0
	} else {
		return len(clients)
	}
}

func SendShutdownRequest() {
	clientsLock.RLock()
	defer clientsLock.RUnlock()

	for _, c := range clients {
		c.logger.Info("Sending shutdown request to client", "address", c.address.String())
		var cmd Cmd
		if configs.GetConfig().Mode == "server" {
			cmd = ShutdownRequest
		} else {
			cmd = ShutdownNotify
		}
		err := c.Write(nil, cmd|WithPadding)
		if err != nil {
			c.logger.Error("Error sending shutdown request", "address", c.address.String(), "error", err)
		}

	}
}

// Under lock
// n is a full packet size (contains HEADER!)
func (c *Client) removeThePacketFromBuffer(n int) {
	copy(c.buf[c.bufOffset:], c.buf[c.bufOffset+n:c.bufSize])
	c.bufSize -= n
}

func (c *Client) Close() error {
	if c.pinger != nil {
		c.pinger.pingTimer.Stop()
		if c.pinger.pongTimeoutTimer != nil {
			c.pinger.pongTimeoutTimer.Stop()
		}
	}
	c.closed = true
	err := c.t.CloseClient(c.address)
	if err != nil {
		return err
	}
	return nil
}
