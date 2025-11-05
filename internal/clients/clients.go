package clients

import (
	"hash/crc32"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"

	"errors"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/crypt"
	"github.com/sem-hub/snake-net/internal/interfaces"
	"github.com/sem-hub/snake-net/internal/network/transport"
	"github.com/sem-hub/snake-net/internal/utils"
)

type State int
type Cmd byte

const (
	BUFSIZE = 131070
	HEADER  = 9 // 2 bytes size + 2 bytes sequence number + 1 byte flags + 4 bytes CRC32
)

const (
	NotFound State = iota
	Connected
	Authenticated
	Ready
	HasData
)

type Client struct {
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
}

var (
	clients     = []*Client{} // XXX make map
	clientsLock sync.Mutex
	logger      *slog.Logger
	tunIf       interfaces.TunInterface
)

func SetTunInterface(tun interfaces.TunInterface) {
	tunIf = tun
}

func (c *Client) GetClientAddr() netip.AddrPort {
	return c.address
}

func (c *Client) GetTunAddrs() []utils.Cidr {
	return c.tunAddrs
}

func NewClient(address netip.AddrPort, t transport.Transport) *Client {
	logger = configs.GetLogger()
	logger.Debug("AddClient", "address", address)
	client := Client{
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
	}
	client.bufSignal = sync.NewCond(client.bufLock)
	client.seqOut.Store(1)

	if len(clients) != 0 && FindClient(address) != nil {
		logger.Error("Client already exists", "address", address)
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
			logger.Debug("client NetLoop after Receive", "len", n, "address", address.String())
			if err != nil {
				logger.Error("client NetLoop Receive error", "err", err)
				return
			}
			c.bufLock.Lock()
			// Write to the end of the buffer
			logger.Debug("client NetLoop put in buf", "len", n, "bufSize", c.bufSize, "address", address.String())
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

// Under lock
// n is a full packet size (contains HEADER)
func (c *Client) removeThePacketFromBuffer(n int) {
	copy(c.buf[c.bufOffset:], c.buf[c.bufOffset+n:c.bufSize])
	c.bufSize -= n
}

// reqSize - minimal size to read
func (c *Client) ReadBuf(reqSize int) (transport.Message, error) {
	logger.Debug("client ReadBuf", "address", c.address.String(), "bufSize", c.bufSize, "bufOffset", c.bufOffset,
		"reqSize", reqSize)
	// If we need to wait for data
	c.bufLock.Lock()
	var lastSize int = 0
	for c.bufSize-c.bufOffset < reqSize {
		lastSize = c.bufSize
		c.bufSignal.Wait()
	}
	// First 2 bytes are size
	// Next 2 bytes are sequence number
	// Next 1 byte is flags
	// Next 4 bytes are CRC32 of the header (of 5 bytes)
	// Next n bytes are message finished with 64 bytes signature
	logger.Debug("client ReadBuf after reading", "address", c.address.String(), "lastSize", lastSize, "bufSize", c.bufSize, "bufOffset", c.bufOffset)
	if c.bufSize-c.bufOffset < HEADER+c.secrets.MinimalSize() {
		c.bufLock.Unlock()
		return nil, errors.New("invalid buffer size")
	}

	data := make([]byte, c.bufSize-c.bufOffset)
	copy(data, c.buf[c.bufOffset:c.bufSize])

	crc := uint32(data[5])<<24 | uint32(data[6])<<16 | uint32(data[7])<<8 | uint32(data[8])
	if crc != crc32.ChecksumIEEE(data[:5]) {
		logger.Debug("ReadBuf CRC32", "address", c.address, "crc", crc, "calculated", crc32.ChecksumIEEE(data[:5]))
		// Safe remove the packet from buffer when we don't believe to n
		copy(c.buf[c.bufOffset:], c.buf[c.bufOffset+(c.bufSize-lastSize):c.bufSize])
		c.bufSize = lastSize

		c.bufLock.Unlock()
		return nil, errors.New("invalid CRC32")
	}
	n := int(data[0])<<8 | int(data[1])
	if n <= 0 || HEADER+n > BUFSIZE {
		// Safe remove the packet from buffer when we don't believe to n
		copy(c.buf[c.bufOffset:], c.buf[c.bufOffset+(c.bufSize-lastSize):c.bufSize])
		c.bufSize = lastSize

		c.bufLock.Unlock()
		return nil, errors.New("invalid message size")
	}

	logger.Debug("client ReadBuf size", "address", c.address.String(), "n", n)
	if HEADER+n > c.bufSize-c.bufOffset {
		c.bufLock.Unlock()
		logger.Error("client Readbuf: incomplete message", "address", c.address.String(), "needed", HEADER+n, "have", c.bufSize-c.bufOffset)
		//return nil, errors.New("incomplete message")
		return c.ReadBuf(HEADER + n)
	}
	seq := uint32(data[2])<<8 | uint32(data[3])
	flags := Cmd(data[4])

	logger.Debug("client ReadBuf seq", "address", c.address, "seq", seq, "expected", c.seqIn)
	// Sanity check of "n"
	if n <= 0 || HEADER+n > BUFSIZE {
		c.removeThePacketFromBuffer(HEADER + n)

		c.bufLock.Unlock()
		return nil, errors.New("invalid message size")
	}
	needResetOffset := false

	// Out of order or lost packets processing
	if seq != c.seqIn {
		logger.Error("client ReadBuf: invalid sequence number", "seq", seq,
			"expected", c.seqIn, "address", c.address, "oooPackets", c.oooPackets)
		// We still hold lock here. Unlock inside the function.
		return c.processOOOP(n, seq)
	} else {
		// In order, reset bufOffset and oooPackets counter
		c.oooPackets = 0
		if c.bufOffset != 0 {
			needResetOffset = true
		}
	}
	c.seqIn++

	if flags != NoneCmd && flags != NoEncryptionCmd {
		logger.Debug("client ReadBuf process command", "address", c.address.String(), "flags", flags)
		return c.processCommand(flags, data, n)
	}

	msg := make([]byte, HEADER+n)
	copy(msg, c.buf[c.bufOffset:c.bufOffset+HEADER+n])

	/* Remove the packet from buffer */
	c.removeThePacketFromBuffer(HEADER + n)
	if needResetOffset {
		logger.Debug("client ReadBuf: reset bufOffset to 0", "address", c.address.String())
		c.bufOffset = 0
	}
	if c.bufSize < 0 {
		logger.Error("client ReadBuf: ", "address", c.address.String(), "bufSize", c.bufSize)
		c.bufSize = 0
		return nil, errors.New("invalid buffer size")
	}
	// Finished working with buf, unlock
	c.bufLock.Unlock()

	// decrypt and verify the packet or just verify if NoEncryptionCmd flag set
	if flags != NoEncryptionCmd {
		logger.Debug("client ReadBuf decrypting", "address", c.address.String())
		data, err := c.secrets.DecryptAndVerify(msg[HEADER : HEADER+n])
		if err != nil {
			logger.Error("client Readbuf: decrypt&verify error", "address", c.address.String(), "error", err)
			return nil, err
		}
		logger.Debug("After decryption", "datalen", len(data), "msglen", len(msg))
		copy(msg[HEADER:], data)
	} else {
		if !c.secrets.Verify(msg[HEADER:HEADER+n-c.secrets.MinimalSize()], msg[HEADER+n-c.secrets.MinimalSize():]) {
			return nil, errors.New("verify error")
		}
		// Remove the signature
		copy(msg, msg[:HEADER+n-c.secrets.MinimalSize()])
		n -= c.secrets.MinimalSize()
	}

	return msg[HEADER : HEADER+n], nil
}

func (c *Client) Write(msg *transport.Message, cmd Cmd) error {
	c.orderSendLock.Lock()
	defer c.orderSendLock.Unlock()

	n := len(*msg)
	logger.Debug("client Write data", "len", n, "address", c.address.String())

	if HEADER+n+c.secrets.MinimalSize() > BUFSIZE {
		return errors.New("invalid message size")
	}
	// Copy message
	logger.Debug("client Write", "address", c.address, "seq", c.seqOut.Load())

	buf := make([]byte, HEADER)

	if cmd != NoEncryptionCmd {
		logger.Debug("client Write encrypting", "address", c.address, "seq", c.seqOut.Load())
		data, err := c.secrets.EncryptAndSeal(*msg)
		if err != nil {
			return err
		}
		buf = append(buf, data...)
	} else {
		buf = append(buf, *msg...)
		signature := c.secrets.Sign(*msg)
		buf = append(buf, signature...)
	}

	n = len(buf) - HEADER
	seq := c.seqOut.Load()
	c.seqOut.Add(1)

	buf[0] = byte(n >> 8)
	buf[1] = byte(n & 0xff)
	buf[2] = byte(seq >> 8)
	buf[3] = byte(seq & 0xff)
	buf[4] = byte(cmd) // flags or command

	crc := crc32.ChecksumIEEE(buf[:5])
	logger.Debug("client Write", "crc", crc)
	buf[5] = byte(crc >> 24)
	buf[6] = byte((crc >> 16) & 0xff)
	buf[7] = byte((crc >> 8) & 0xff)
	buf[8] = byte(crc & 0xff)

	logger.Debug("client Write final", "address", c.address, "n", n, "bufsize", len(buf))
	err := c.t.Send(c.address, &buf)
	if err != nil {
		logger.Debug("client Write send error", "error", err, "address", c.address, "seq", seq)
		return err
	}
	logger.Debug("client Write sent", "len", len(buf), "address", c.address.String(), "seq", seq)
	c.sentBuffer.Push(buf)
	return nil
}

func (c *Client) Close() error {
	err := c.t.CloseClient(c.address)
	if err != nil {
		return err
	}
	return nil
}
