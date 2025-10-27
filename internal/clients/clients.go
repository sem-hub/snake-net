package clients

import (
	"hash/crc32"
	"log/slog"
	"math/rand"
	"net"
	"net/netip"
	"sync"

	"errors"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/crypt"
	"github.com/sem-hub/snake-net/internal/network/transport"
)

type State int

const (
	BUFSIZE = 65535
	HEADER  = 9 // 2 bytes size + 2 bytes sequence number + 1 byte flags + 4 bytes CRC32
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
	address    netip.AddrPort
	tunAddr    net.Addr
	tunAddr6   net.Addr
	t          transport.Transport
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
	clients     = []*Client{} // XXX make map
	clientsLock sync.Mutex
	logger      *slog.Logger
)

func (c *Client) GetClientAddr() netip.AddrPort {
	return c.address
}

func NewClient(address netip.AddrPort, t transport.Transport) *Client {
	logger = configs.GetLogger()
	logger.Debug("AddClient", "address", address)
	client := Client{
		address:    address,
		tunAddr:    nil,
		tunAddr6:   nil,
		t:          t,
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

func RemoveClient(address netip.AddrPort) {
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

func FindClient(address netip.AddrPort) *Client {
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
	logger.Debug("SetClientState", "address", c.address.String(), "state", state)
}

func GetClientCount() int {
	if clients == nil {
		return 0
	} else {
		return len(clients)
	}
}

func (c *Client) RunNetLoop(address netip.AddrPort) {
	logger.Debug("RunNetLoop", "address", address)
	// read data from network into c.buf
	// when data is available, send signal to c.bufSignal
	// main loop will read data from c.buf
	go func() {
		for {
			logger.Debug("client NetLoop waiting for data", "address", address.String())
			msg, n, err := c.t.Receive(address)
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
			logger.Debug("client NetLoop put", "len", n, "from", address.String())
		}
	}()
}

func (c *Client) ReadBuf() (transport.Message, error) {
	logger.Debug("client ReadBuf", "address", c.address.String(), "bufSize", c.bufSize, "bufOffset", c.bufOffset)
	// If we need to wait for data
	c.bufLock.Lock()
	for c.bufSize-c.bufOffset <= 0 {
		c.bufSignal.Wait()
	}
	// First 2 bytes are size
	// Next 2 bytes are sequence number
	// Next 1 byte is flags
	// Next 4 bytes are CRC32 of the header (of 5 bytes)
	// Next n bytes are message finished with 64 bytes signature
	logger.Debug("client ReadBuf after reading", "address", c.address.String(), "bufSize", c.bufSize, "bufOffset", c.bufOffset)
	if c.bufSize-c.bufOffset < ADDSIZE {
		c.bufLock.Unlock()
		return nil, errors.New("invalid buffer size")
	}
	/*data, err := c.secrets.CryptDecrypt(c.buf[c.bufOffset:c.bufSize])
	if err != nil {
		c.bufLock.Unlock()
		return nil, err
	}*/
	data := make([]byte, c.bufSize-c.bufOffset)
	copy(data, c.buf[c.bufOffset:c.bufSize])

	crc := uint32(int(data[5])<<24 | int(data[6])<<16 | int(data[7])<<8 | int(data[8]))
	if crc != crc32.ChecksumIEEE(data[:5]) {
		c.bufLock.Unlock()
		return nil, errors.New("invalid CRC32")
	}
	n := int(data[0])<<8 | int(data[1])
	logger.Debug("client ReadBuf size", "address", c.address.String(), "n", n)
	seq := int(data[2])<<8 | int(data[3])
	flags := data[4]
	if flags == 0xff {
		logger.Debug("client ReadBuf flags 0xff, closing connection", "address", c.address.String())
		c.bufLock.Unlock()
		return nil, errors.New("connection closed by peer")
	}
	//logger.Debug("client ReadBuf flags", "address", c.address, "flags", flags)
	logger.Debug("client ReadBuf seq", "address", c.address, "seq", seq, "expected", c.seqIn)
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
			logger.Error("client ReadBuf: too many out of order packets, reset buffer", "address", c.address.String())
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
		logger.Debug("client ReadBuf: reset bufOffset to 0", "address", c.address.String())
		c.bufOffset = 0
	}
	if c.bufSize < 0 {
		logger.Error("client ReadBuf: ", "address", c.address.String(), "bufSize", c.bufSize)
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
	logger.Debug("client Write data", "len", n, "address", c.address.String())
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
	crc := crc32.ChecksumIEEE(buf[:5])
	buf[5] = byte(crc >> 24)
	buf[6] = byte((crc >> 16) & 0xff)
	buf[7] = byte((crc >> 8) & 0xff)
	buf[8] = byte(crc & 0xff)
	// Copy message
	logger.Debug("client Write", "address", c.address, "seq", c.seqOut)
	copy(buf[HEADER:n+HEADER], *msg)
	/*data, err := c.secrets.CryptDecrypt(buf[:n+HEADER])
	if err != nil {
		return err
	}
	copy(buf[:n+HEADER], data)*/

	signature := c.secrets.Sign(buf[:n+HEADER])
	copy(buf[n+HEADER:], signature)
	err := c.t.Send(c.address, &buf)
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

func (c *Client) Close() error {
	err := c.t.CloseClient(c.address)
	if err != nil {
		return err
	}
	return nil
}
