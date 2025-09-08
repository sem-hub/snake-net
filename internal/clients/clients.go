package clients

import (
	"bytes"
	"net"
	"sync"

	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"

	"errors"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/crypt"
	"github.com/sem-hub/snake-net/internal/network/transport"
)

type State int

const (
	NotFound State = iota
	Connected
	Authenticated
	Ready
	HasData
)

type Client struct {
	address   net.Addr
	tunAddr   net.Addr
	t         transport.Transport
	conn      net.Conn
	state     State
	secrets   *crypt.Secrets
	buf       []byte
	bufLock   *sync.Mutex
	bufSignal chan int
	offset    int
	bufSize   int
	seqIn     int
	seqOut    int
}

var (
	clients = []*Client{}
	lock    sync.Mutex
)

func (c *Client) GetClientConn(address net.Addr) net.Conn {
	return c.conn
}

func (c *Client) GetClientAddr() net.Addr {
	return c.address
}

func NewClient(address net.Addr, t transport.Transport, conn net.Conn) *Client {
	lock.Lock()
	defer lock.Unlock()

	logging := configs.GetLogger()
	logging.Debug("AddClient", "address", address)
	client := Client{
		address:   address,
		tunAddr:   nil,
		t:         t,
		conn:      conn,
		state:     Connected,
		secrets:   nil,
		buf:       make([]byte, transport.BUFSIZE),
		bufLock:   &sync.Mutex{},
		bufSignal: make(chan int, 100),
		offset:    0,
		bufSize:   0,
		seqIn:     0,
		seqOut:    0,
	}
	clients = append(clients, &client)
	return &client
}

func (c *Client) AddTunAddressToClient(tunAddr net.Addr) {
	configs.GetLogger().Debug("AddTunAddressToClient", "addr", tunAddr)
	c.tunAddr = tunAddr
}

func (c *Client) AddSecretsToClient(s *crypt.Secrets) {
	c.secrets = s
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

func FindClient(address net.Addr) *Client {
	lock.Lock()
	defer lock.Unlock()

	for _, c := range clients {
		if c.address.String() == address.String() {
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
	//configs.GetLogger().Debug("SetClientState", "address", address, "state", state)
}

func GetClientCount() int {
	if clients == nil {
		return 0
	} else {
		return len(clients)
	}
}

func (c *Client) RunNetLoop(address net.Addr) {
	logger := configs.GetLogger()
	logger.Debug("RunNetLoop", "address", address)
	// read data from network into c.buf
	// when data is available, send signal to c.bufSignal channel
	// main loop will read data from c.buf
	go func() {
		for {
			msg, n, _, err := c.t.Receive(c.conn)
			if err != nil {
				logger.Error("NetLoop error", "err", err)
				return
			}
			logger.Debug("NetLoop", "len", n, "from", address)
			c.bufLock.Lock()
			copy(c.buf[c.offset:], msg[:n])
			c.offset += n
			c.bufSize += n
			c.bufLock.Unlock()
			logger.Debug("NetLoop Unlock")
			c.bufSignal <- 1
			logger.Debug("NetLoop receive finished")
		}
	}()
}

func (c *Client) ReadBuf() (transport.Message, error) {
	// XXX decrypt. check and read
	configs.GetLogger().Debug("ReadBuf", "bufSize", c.bufSize)
	<-c.bufSignal
	configs.GetLogger().Debug("ReadBuf got signal")
	if c.bufSize > 0 {
		c.bufLock.Lock()
		msg := make([]byte, c.bufSize)
		copy(msg, c.buf[:c.bufSize])
		c.offset = 0
		c.bufSize = 0
		c.bufLock.Unlock()
		return msg, nil
	}
	return nil, nil
}

func (c *Client) Write(msg *transport.Message) error {
	// XXX Sign, Encrype and send
	err := c.t.Send(c.address, c.conn, msg)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) ECDH() error {
	tempPrivateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	tempPublicKey := tempPrivateKey.PublicKey()

	buf, err := x509.MarshalPKIXPublicKey(tempPublicKey)
	if err != nil {
		return errors.New("marshaling ecdh public key: " + err.Error())
	}

	//configs.GetLogger().Debug("Write public key", "len", len(buf), "buf", buf)
	err = c.Write(&buf)
	if err != nil {
		return err
	}
	buf, err = c.ReadBuf()
	if err != nil {
		return err
	}
	//logging.Debug("Read public key", "len", len(buf), "buf", buf)

	publicKey, err := x509.ParsePKIXPublicKey(buf)
	if err != nil {
		return errors.New("parsing marshaled ecdh public key: " + err.Error())
	}
	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("converting marshaled public key to ecdsa public key")

	}
	parsedKey, _ := ecdsaPublicKey.ECDH()

	c.secrets.SharedSecret, err = tempPrivateKey.ECDH(parsedKey)
	if err != nil {
		return err
	}
	//fmt.Println("shared secret: ", s.SharedSecret)
	c.secrets.SessionPublicKey, c.secrets.SessionPrivateKey, err =
		ed25519.GenerateKey(bytes.NewReader(c.secrets.SharedSecret))
	if err != nil {
		return err
	}
	return nil
}

func getDstIP(packet []byte) net.Addr {
	if len(packet) < 1 {
		return nil
	}
	version := packet[0] >> 4 // First 4 bits
	if version == 4 {
		return &net.IPAddr{IP: packet[16:20]} // IPv4 address in bytes 16-19
	}
	if version == 6 {
		return &net.IPAddr{IP: packet[24:40]} // IPv6 address in bytes 24-39
	}
	return nil
}

func Route(data []byte) bool {
	lock.Lock()
	clientsCopy := make([]*Client, len(clients))
	copy(clientsCopy, clients)
	lock.Unlock()
	logging := configs.GetLogger()

	address := getDstIP(data)
	if address == nil {
		logging.Debug("Route: no destination IP found. Ignore.")
		return false
	}
	logging.Debug("Route", "address", address, "len", len(data))
	// XXX read route table
	found := false
	for _, c := range clientsCopy {
		logging.Debug("Route", "address", address, "client", c.tunAddr)
		if c.tunAddr.String() == address.String() {
			if c.secrets != nil {
				go func(cl *Client) {
					err := cl.Write(&data)
					if err != nil {
						logging.Error("Route write", "error", err)
					}
				}(c)
			}
			found = true
			break
		}
	}
	myIP, _, err := net.ParseCIDR(configs.GetConfig().TunAddr)
	if err != nil {
		logging.Error("Route", "error", err)
		return true
	}
	if !found && myIP.String() != address.String() {
		logging.Debug("Route: no matching client found. Send to all clients")
		for _, c := range clientsCopy {
			if c.secrets != nil {
				go func(cl *Client) {
					err := cl.Write(&data)
					if err != nil {
						logging.Error("Route write", "error", err)
					}
				}(c)
			}
		}
	}
	return found
}
