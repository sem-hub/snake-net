package clients

import (
	"bytes"
	"log/slog"
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
	bufSize   int
	seqIn     int
	seqOut    int
}

var (
	clients     = []*Client{}
	clientsLock sync.Mutex
	logger      *slog.Logger
)

func (c *Client) GetClientConn(address net.Addr) net.Conn {
	return c.conn
}

func (c *Client) GetClientAddr() net.Addr {
	return c.address
}

func NewClient(address net.Addr, t transport.Transport, conn net.Conn) *Client {
	logger = configs.GetLogger()
	logger.Debug("AddClient", "address", address)
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
		bufSize:   0,
		seqIn:     1,
		seqOut:    1,
	}

	if len(clients) != 0 && FindClient(address) != nil {
		logger.Error("Client already exists", "address", address)
	} else {
		clientsLock.Lock()
		clients = append(clients, &client)
		clientsLock.Unlock()
	}
	return &client
}

func (c *Client) AddTunAddressToClient(tunAddr net.Addr) {
	logger.Debug("AddTunAddressToClient", "addr", tunAddr)
	c.tunAddr = tunAddr
}

func (c *Client) AddSecretsToClient(s *crypt.Secrets) {
	c.secrets = s
}

func RemoveClient(address net.Addr) {
	clientsLock.Lock()
	defer clientsLock.Unlock()
	for i, c := range clients {
		if c.address.String() == address.String() {
			clients = append(clients[:i], clients[i+1:]...)
			break
		}
	}
}

func FindClient(address net.Addr) *Client {
	clientsLock.Lock()
	defer clientsLock.Unlock()

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
	//logger.Debug("SetClientState", "address", address, "state", state)
}

func GetClientCount() int {
	if clients == nil {
		return 0
	} else {
		return len(clients)
	}
}

func (c *Client) RunNetLoop(address net.Addr) {
	logger.Debug("RunNetLoop", "address", address)
	// read data from network into c.buf
	// when data is available, send signal to c.bufSignal channel
	// main loop will read data from c.buf
	go func() {
		for {
			logger.Debug("NetLoop waiting for data", "address", address)
			msg, n, _, err := c.t.Receive(c.conn, address)
			logger.Debug("NetLoop Receive", "len", n, "err", err)
			if err != nil {
				logger.Error("NetLoop Receive error", "err", err)
				return
			}
			c.bufLock.Lock()
			// Write to the end of the buffer
			copy(c.buf[c.bufSize:], msg[:n])
			c.bufSize += n
			if n > 0 {
				c.bufSignal <- 1
			}
			c.bufLock.Unlock()
			logger.Debug("NetLoop", "len", n, "from", address)
		}
	}()
}

func (c *Client) ReadBuf() (transport.Message, error) {
	// XXX decrypt. check and read
	logger.Debug("ReadBuf", "bufSize", c.bufSize)
	for c.bufSize == 0 {
		<-c.bufSignal
	}
	c.bufLock.Lock()
	// Read message size and sequence number
	// First 2 bytes are size
	// Next 2 bytes are sequence number
	// Next n bytes are message
	//logger.Debug("ReadBuf", "bufSize", c.bufSize)
	if c.bufSize < 4 {
		c.bufLock.Unlock()
		return nil, errors.New("invalid buffer size")
	}
	n := int(c.buf[0])<<8 | int(c.buf[1])
	//logger.Debug("ReadBuf size", "n", n)
	seq := int(c.buf[2])<<8 | int(c.buf[3])
	logger.Debug("ReadBuf seq", "seq", seq, "expected", c.seqIn)
	if n <= 0 || n > transport.BUFSIZE-4 {
		c.bufLock.Unlock()
		return nil, errors.New("invalid message size")
	}
	if seq != c.seqIn {
		logger.Error("ReadBuf: invalid sequence number", "seq", seq,
			"expected", c.seqIn)
		// We can choose to resync here, but for now just return an error
		copy(c.buf, c.buf[n+4:c.bufSize])
		c.bufSize -= n + 4
		c.bufLock.Unlock()
		return nil, errors.New("invalid sequence number")
	}
	c.seqIn++
	if c.seqIn > 65535 {
		c.seqIn = 0
	}
	if c.bufSize < n+4 {
		c.bufLock.Unlock()
		return nil, errors.New("incomplete message")
	}
	msg := make([]byte, n)
	copy(msg, c.buf[4:n+4])
	copy(c.buf, c.buf[n+4:c.bufSize])
	c.bufSize -= n + 4
	if c.bufSize < 0 {
		logger.Error("ReadBuf: invalid buffer size", "bufSize", c.bufSize)
		c.bufSize = 0
		return nil, errors.New("invalid buffer size")
	}
	c.bufLock.Unlock()
	return msg, nil
}

func (c *Client) Write(msg *transport.Message) error {
	// XXX Sign, Encrype and send
	n := len(*msg)
	logger.Debug("Write data", "len", n)
	// First 2 bytes are size
	// Next 2 bytes are sequence number
	// Next n bytes are message
	if n > transport.BUFSIZE-4 {
		return errors.New("invalid message size")
	}
	buf := make([]byte, n+4)
	buf[0] = byte(n >> 8)
	buf[1] = byte(n & 0xff)
	buf[2] = byte(c.seqOut >> 8)
	buf[3] = byte(c.seqOut & 0xff)
	logger.Debug("Write", "seq", c.seqOut)
	c.seqOut++
	if c.seqOut > 65535 {
		c.seqOut = 0
	}
	copy(buf[4:n+4], *msg)
	err := c.t.Send(c.address, c.conn, &buf)
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

	logger.Debug("Write public key", "len", len(buf), "buf", buf)
	err = c.Write(&buf)
	if err != nil {
		return err
	}
	buf, err = c.ReadBuf()
	if err != nil {
		return err
	}
	logger.Debug("Read public key", "len", len(buf), "buf", buf)

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
	clientsLock.Lock()
	clientsCopy := make([]Client, len(clients))
	for i, c := range clients {
		clientsCopy[i] = *c
	}
	clientsLock.Unlock()

	address := getDstIP(data)
	if address == nil {
		logger.Debug("Route: no destination IP found. Ignore.")
		return false
	}
	logger.Debug("Route", "address", address, "len", len(data))
	// XXX read route table
	found := false
	for _, c := range clientsCopy {
		logger.Debug("Route", "address", address, "client", c.tunAddr)
		if c.tunAddr != nil && c.tunAddr.String() == address.String() && c.GetClientState() == Ready {
			if c.secrets != nil {
				go func(cl *Client) {
					c := FindClient(cl.address)
					err := c.Write(&data)
					if err != nil {
						logger.Error("Route write", "error", err)
					}
				}(&c)
			}
			found = true
			break
		}
	}
	myIP, _, err := net.ParseCIDR(configs.GetConfig().TunAddr)
	if err != nil {
		logger.Error("Route", "error", err)
		return true
	}
	if !found && myIP.String() != address.String() {
		logger.Debug("Route: no matching client found. Send to all clients")
		for _, c := range clientsCopy {
			if c.secrets != nil && c.GetClientState() == Ready {
				go func(cl *Client) {
					c := FindClient(cl.address)
					err := c.Write(&data)
					if err != nil {
						logger.Error("Route write", "error", err)
					}
				}(&c)
			}
		}
	}
	return found
}
