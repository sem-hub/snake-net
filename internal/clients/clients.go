package clients

import (
	"log/slog"
	"math/rand"
	"net"
	"sync"

	"errors"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/crypt"
	"github.com/sem-hub/snake-net/internal/network/transport"
)

type State int

const (
	BUFSIZE = 65535
	HEADER  = 5 // 2 bytes size + 2 bytes sequence number + 1 byte flags
	ADDSIZE = HEADER + crypt.SIGNLEN
)

const (
	NotFound State = iota
	Connected
	Authenticated
	Ready
	HasData
)

type Client struct {
	address    net.Addr
	tunAddr    net.Addr
	tunAddr6   net.Addr
	t          transport.Transport
	conn       net.Conn
	state      State
	secrets    *crypt.Secrets
	buf        []byte
	bufLock    *sync.Mutex
	bufSignal  *sync.Cond
	bufSize    int
	bufOffset  int
	seqIn      int
	seqOut     int
	seqOutLock *sync.Mutex
	oooPackets int
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
		address:    address,
		tunAddr:    nil,
		tunAddr6:   nil,
		t:          t,
		conn:       conn,
		state:      Connected,
		secrets:    nil,
		buf:        make([]byte, BUFSIZE),
		bufLock:    &sync.Mutex{},
		bufSize:    0,
		bufOffset:  0,
		seqIn:      1,
		seqOut:     1,
		seqOutLock: &sync.Mutex{},
		oooPackets: 0,
	}
	client.bufSignal = sync.NewCond(client.bufLock)

	if len(clients) != 0 && FindClient(address) != nil {
		logger.Error("Client already exists", "address", address)
	} else {
		clientsLock.Lock()
		clients = append(clients, &client)
		clientsLock.Unlock()
	}
	return &client
}

func (c *Client) AddTunAddressToClient(tunAddr net.Addr, tunAddr6 net.Addr) {
	logger.Debug("AddTunAddressToClient", "addr", tunAddr, "addr6", tunAddr6)
	c.tunAddr = tunAddr
	c.tunAddr6 = tunAddr6
}

func (c *Client) AddSecretsToClient(s *crypt.Secrets) {
	c.secrets = s
}

func RemoveClient(address net.Addr) {
	clientsLock.Lock()
	defer clientsLock.Unlock()
	for i, c := range clients {
		if c.address.String() == address.String() {
			c.Close()
			logger.Debug("RemoveClient", "address", address)
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
	logger.Debug("SetClientState", "address", c.address, "state", state)
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
	// when data is available, send signal to c.bufSignal
	// main loop will read data from c.buf
	go func() {
		for {
			logger.Debug("client NetLoop waiting for data", "address", address)
			msg, n, _, err := c.t.Receive(c.conn, address)
			logger.Debug("client NetLoop after Receive", "len", n, "err", err)
			if err != nil {
				logger.Error("client NetLoop Receive error", "err", err)
				return
			}
			c.bufLock.Lock()
			// Write to the end of the buffer
			copy(c.buf[c.bufSize:], msg[:n])
			c.bufSize += n
			if n > 0 {
				c.bufSignal.Signal()
			}
			c.bufLock.Unlock()
			logger.Debug("client NetLoop put", "len", n, "from", address)
		}
	}()
}

func (c *Client) ReadBuf() (transport.Message, error) {
	logger.Debug("client ReadBuf", "address", c.address, "bufSize", c.bufSize, "bufOffset", c.bufOffset)
	// If we need to wait for data
	c.bufLock.Lock()
	for c.bufSize-c.bufOffset <= 0 {
		c.bufSignal.Wait()
	}
	// First 2 bytes are size
	// Next 2 bytes are sequence number
	// Next 1 byte is flags
	// Next n bytes are message finished with 64 bytes signature
	logger.Debug("client ReadBuf after reading", "address", c.address, "bufSize", c.bufSize, "bufOffset", c.bufOffset)
	if c.bufSize-c.bufOffset < ADDSIZE {
		c.bufLock.Unlock()
		return nil, errors.New("invalid buffer size")
	}
	data, err := c.secrets.CryptDecrypt(c.buf[c.bufOffset:c.bufSize])
	if err != nil {
		c.bufLock.Unlock()
		return nil, err
	}
	n := int(data[0])<<8 | int(data[1])
	logger.Debug("client ReadBuf size", "address", c.address, "n", n)
	seq := int(data[2])<<8 | int(data[3])
	flags := data[4]
	if flags == 0xff {
		logger.Debug("client ReadBuf flags 0xff, closing connection", "address", c.address)
		c.bufLock.Unlock()
		return nil, errors.New("connection closed by peer")
	}
	//logger.Debug("client ReadBuf flags", "address", c.address, "flags", flags)
	//logger.Debug("client ReadBuf seq", "address", c.address, "seq", seq, "expected", c.seqIn)
	if n <= 0 || n+ADDSIZE > BUFSIZE {
		c.bufLock.Unlock()
		return nil, errors.New("invalid message size")
	}
	needResetOffset := false

	if seq != c.seqIn {
		logger.Error("client ReadBuf: invalid sequence number", "seq", seq,
			"expected", c.seqIn, "address", c.address)
		// OutOfOrder leave packet in buffer and restart reading
		c.oooPackets++
		if c.oooPackets > 100 {
			// Too many out of order packets, reset buffer
			logger.Error("client ReadBuf: too many out of order packets, reset buffer", "address", c.address)
			return nil, errors.New("too many out of order packets")
		}
		c.bufOffset += n + ADDSIZE
		c.bufLock.Unlock()
		return c.ReadBuf()
	} else {
		// In order, reset bufOffset and oooPackets counter
		c.oooPackets = 0
		if c.bufOffset != 0 {
			needResetOffset = true
		}
	}
	c.seqIn++
	if c.seqIn > 65535 {
		c.seqIn = 0
	}
	if c.bufSize-c.bufOffset < n+ADDSIZE {
		c.bufLock.Unlock()
		return nil, errors.New("incomplete message")
	}
	msg := make([]byte, n+ADDSIZE)
	copy(msg, c.buf[c.bufOffset:c.bufOffset+n+ADDSIZE])
	copy(c.buf[c.bufOffset:], c.buf[c.bufOffset+n+ADDSIZE:c.bufSize])
	c.bufSize -= n + ADDSIZE
	if needResetOffset {
		logger.Debug("client ReadBuf: reset bufOffset to 0", "address", c.address)
		c.bufOffset = 0
	}
	if c.bufSize < 0 {
		logger.Error("client ReadBuf: ", "address", c.address, "bufSize", c.bufSize)
		c.bufSize = 0
		return nil, errors.New("invalid buffer size")
	}
	c.bufLock.Unlock()
	if !c.secrets.Verify(msg[:n+HEADER], msg[n+HEADER:]) {
		return nil, errors.New("invalid signature")
	}
	return data[HEADER : n+HEADER], nil
}

func (c *Client) Write(msg *transport.Message) error {
	n := len(*msg)
	logger.Debug("client Write data", "len", n, "address", c.address)
	// First 2 bytes are size
	// Next 2 bytes are sequence number
	// Next n bytes are message
	if n+ADDSIZE > BUFSIZE {
		return errors.New("invalid message size")
	}
	buf := make([]byte, n+ADDSIZE)
	buf[0] = byte(n >> 8)
	buf[1] = byte(n & 0xff)
	c.seqOutLock.Lock()
	buf[2] = byte(c.seqOut >> 8)
	buf[3] = byte(c.seqOut & 0xff)
	buf[4] = 0 // flags
	c.seqOut++
	if c.seqOut > 65535 {
		c.seqOut = 0
	}
	c.seqOutLock.Unlock()
	//logger.Debug("client Write", "address", c.address, "seq", c.seqOut)
	copy(buf[HEADER:n+HEADER], *msg)
	data, err := c.secrets.CryptDecrypt(buf[:n+HEADER])
	if err != nil {
		return err
	}
	copy(buf[:n+HEADER], data)

	signature := c.secrets.Sign(buf[:n+HEADER])
	copy(buf[n+HEADER:], signature)
	err = c.t.Send(c.address, c.conn, &buf)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) WriteWithXORAndPadding(msg []byte, needXOR bool) error {
	paddingSize := rand.Intn(64)
	buf := make([]byte, len(msg)+paddingSize)
	copy(buf, msg)
	padding := make([]byte, paddingSize)
	for i := 0; i < paddingSize; i++ {
		padding[i] = byte(rand.Intn(256))
	}
	// 0 byte to separate message and padding
	copy(buf[len(msg):], padding)
	if needXOR {
		c.XOR(&buf)
	}
	logger.Debug("client WriteWithPadding", "len", len(buf), "data", len(msg), "paddingSize", paddingSize, "address", c.address)
	return c.Write(&buf)
}

func (c *Client) XOR(data *[]byte) {
	c.secrets.XOR(data)
}

// XXX should not tie to tcp transport only
func (c *Client) Close() error {
	// Only for stream transports
	if c.t.GetType() == "stream" {
		if c.t.GetName() == "tcp" {
			tcpconn := c.conn.(*net.TCPConn)
			tcpconn.Close()
		}
	}
	return nil
}
