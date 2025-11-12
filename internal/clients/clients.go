package clients

import (
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/crypt"
	"github.com/sem-hub/snake-net/internal/interfaces"
	"github.com/sem-hub/snake-net/internal/network/transport"
	"github.com/sem-hub/snake-net/internal/utils"
)

type State int
type Cmd byte

const (
	BUFSIZE = 524288 // 512 KB
	HEADER  = 9      // 2 bytes size + 2 bytes sequence number + 1 byte flags + 4 bytes CRC32
)

const (
	NotFound State = iota
	Connected
	Authenticated
	Ready
	HasData
)

type Client struct {
	logger        *slog.Logger
	address       netip.AddrPort
	tunAddrs      []utils.Cidr
	t             transport.Transport
	state         State
	secrets       *crypt.Secrets
	buf           []byte
	bufLock       *sync.Mutex
	bufSignal     *sync.Cond
	bufSize       int
	bufOffset     int
	seqIn         uint32 // always read/write under bugLock
	seqOut        *atomic.Uint32
	oooPackets    int
	sentBuffer    *utils.CircularBuffer
	orderSendLock *sync.Mutex
	closed        bool
	id            string
}

var (
	clients     = []*Client{} // XXX make map
	clientsLock sync.Mutex
	tunIf       interfaces.TunInterface
)

func GetClientsList() []*Client {
	return clients
}

func SetTunInterface(tun interfaces.TunInterface) {
	tunIf = tun
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
	logger := configs.InitLogger("client")
	logger.Debug("AddClient", "address", address)
	client := Client{
		logger:        logger,
		address:       address,
		tunAddrs:      nil,
		t:             t,
		state:         Connected,
		secrets:       nil,
		buf:           make([]byte, BUFSIZE),
		bufLock:       &sync.Mutex{},
		bufSize:       0,
		bufOffset:     0,
		seqIn:         1,
		seqOut:        &atomic.Uint32{},
		oooPackets:    0,
		sentBuffer:    utils.NewCircularBuffer(100),
		orderSendLock: &sync.Mutex{},
		closed:        false,
		id:            "",
	}
	client.bufSignal = sync.NewCond(client.bufLock)
	client.seqOut.Store(1)

	if len(clients) != 0 && FindClient(address) != nil {
		logger.Info("Client already exists", "address", address)
	} else {
		clientsLock.Lock()
		clients = append(clients, &client)
		clientsLock.Unlock()
	}
	return &client
}

func (c *Client) AddTunAddressesToClient(cidrs []utils.Cidr) {
	c.tunAddrs = append(c.tunAddrs, cidrs...)
}

func (c *Client) AddSecretsToClient(s *crypt.Secrets) {
	c.secrets = s
}

func RemoveClient(address netip.AddrPort) {
	clientsLock.Lock()
	defer clientsLock.Unlock()
	for i, c := range clients {
		if c.address == address {
			c.Close()
			c.logger.Debug("RemoveClient", "address", address)
			clients = append(clients[:i], clients[i+1:]...)
			break
		}
	}
}

func FindClient(address netip.AddrPort) *Client {
	clientsLock.Lock()
	defer clientsLock.Unlock()

	for _, c := range clients {
		if c.address == address {
			return c
		}
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

func GetClientCount() int {
	if clients == nil {
		return 0
	} else {
		return len(clients)
	}
}

func SendAllShutdownRequest() {
	clientsLock.Lock()
	defer clientsLock.Unlock()

	for _, c := range clients {
		c.logger.Info("Sending shutdown request to client", "address", c.address.String())
		buf := MakePadding()
		err := c.Write(&buf, ShutdownRequest)
		if err != nil {
			c.logger.Error("Error sending shutdown request", "address", c.address.String(), "error", err)
		}
	}
}

func (c *Client) RunNetLoop(address netip.AddrPort) {
	c.logger.Debug("RunNetLoop", "address", address)
	// read data from network into c.buf
	// when data is available, send signal to c.bufSignal
	// main loop will read data from c.buf
	go func() {
		for {
			c.logger.Debug("client NetLoop waiting for data", "address", address.String())
			msg, n, err := c.t.Receive(address)
			if err != nil {
				c.logger.Error("client NetLoop Receive error", "err", err)
				c.bufSignal.Signal()
				// We got an error. Mostly it will EOF(XXX), so close and remove the client
				c.SetClientState(NotFound)
				RemoveClient(c.address)
				if configs.GetConfig().Mode == "client" {
					tunIf.Close()
				}
				break
			}
			c.bufLock.Lock()
			// Write to the end of the buffer
			c.logger.Debug("client NetLoop put in buf", "len", n, "bufSize", c.bufSize, "address", address.String())
			copy(c.buf[c.bufSize:], msg[:n])
			c.bufSize += n
			if n > 0 {
				c.bufSignal.Signal()
			}
			c.bufLock.Unlock()
			c.logger.Debug("client NetLoop put", "len", n, "from", address.String())
		}
		c.logger.Debug("client NetLoop exits", "address", address.String())
	}()
}

// Under lock
// n is a full packet size (contains HEADER)
func (c *Client) removeThePacketFromBuffer(n int) {
	copy(c.buf[c.bufOffset:], c.buf[c.bufOffset+n:c.bufSize])
	c.bufSize -= n
}

func (c *Client) Close() error {
	c.closed = true
	err := c.t.CloseClient(c.address)
	if err != nil {
		return err
	}
	return nil
}
