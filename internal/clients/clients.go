package clients

import (
	"hash/crc32"
	"log/slog"
	"net"
	"net/netip"
	"sync"

	"errors"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/crypt"
	"github.com/sem-hub/snake-net/internal/network/transport"
	"github.com/sem-hub/snake-net/internal/utils"
)

type State int
type Cmd byte

const (
	BUFSIZE = 131070
	HEADER  = 9                      // 2 bytes size + 2 bytes sequence number + 1 byte flags + 4 bytes CRC32
	ADDSIZE = HEADER + crypt.SIGNLEN // 9+64=73
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
	tunAddr       net.Addr
	tunAddr6      net.Addr
	t             transport.Transport
	state         State
	secrets       *crypt.Secrets
	buf           []byte
	bufLock       *sync.Mutex
	bufSignal     *sync.Cond
	bufSize       int
	bufOffset     int
	seqIn         int
	seqOut        int
	seqOutLock    *sync.Mutex
	oooPackets    int
	sentBuffer    *utils.CircularBuffer
	orderSendLock *sync.Mutex
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
		address:       address,
		tunAddr:       nil,
		tunAddr6:      nil,
		t:             t,
		state:         Connected,
		secrets:       nil,
		buf:           make([]byte, BUFSIZE),
		bufLock:       &sync.Mutex{},
		bufSize:       0,
		bufOffset:     0,
		seqIn:         1,
		seqOut:        1,
		seqOutLock:    &sync.Mutex{},
		oooPackets:    0,
		sentBuffer:    utils.NewCircularBuffer(100),
		orderSendLock: &sync.Mutex{},
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

// Executed under lock
func (c *Client) lookInBufferForSeq(seq int) bool {
	offset := 0
	for offset < c.bufSize {
		if c.bufSize-offset < ADDSIZE {
			return false
		}
		crc := uint32(int(c.buf[offset+5])<<24 | int(c.buf[offset+6])<<16 | int(c.buf[offset+7])<<8 | int(c.buf[offset+8]))
		if crc != crc32.ChecksumIEEE(c.buf[offset:offset+5]) {
			logger.Debug("lookInBufferForSeq CRC32", "address", c.address, "crc", crc, "calculated", crc32.ChecksumIEEE(c.buf[offset:offset+5]))
			return false
		}
		// Get data size and sequence number
		n := int(c.buf[offset])<<8 | int(c.buf[offset+1])
		packetSeq := int(c.buf[offset+2])<<8 | int(c.buf[offset+3])
		logger.Debug("lookInBufferForSeq packet in buffer", "seq", packetSeq, "size", n, "address", c.address.String())
		if packetSeq == seq {
			c.bufOffset = offset
			return true
		}
		offset += n + ADDSIZE
	}
	return false
}

// Under lock
func (c *Client) removeThePacketFromBuffer(n int) {
	copy(c.buf[c.bufOffset:], c.buf[c.bufOffset+n+ADDSIZE:c.bufSize])
	c.bufSize -= n + ADDSIZE
}

func (c *Client) ReadBuf() (transport.Message, error) {
	logger.Debug("client ReadBuf", "address", c.address.String(), "bufSize", c.bufSize, "bufOffset", c.bufOffset)
	// If we need to wait for data
	c.bufLock.Lock()
	var lastSize int = 0
	for c.bufSize-c.bufOffset <= 0 {
		lastSize = c.bufSize
		c.bufSignal.Wait()
	}
	// First 2 bytes are size
	// Next 2 bytes are sequence number
	// Next 1 byte is flags
	// Next 4 bytes are CRC32 of the header (of 5 bytes)
	// Next n bytes are message finished with 64 bytes signature
	logger.Debug("client ReadBuf after reading", "address", c.address.String(), "lastSize", lastSize, "bufSize", c.bufSize, "bufOffset", c.bufOffset)
	if c.bufSize-c.bufOffset < ADDSIZE {
		c.bufLock.Unlock()
		return nil, errors.New("invalid buffer size")
	}

	data := make([]byte, c.bufSize-c.bufOffset)
	copy(data, c.buf[c.bufOffset:c.bufSize])

	crc := uint32(int(data[5])<<24 | int(data[6])<<16 | int(data[7])<<8 | int(data[8]))
	if crc != crc32.ChecksumIEEE(data[:5]) {
		logger.Debug("Write CRC32", "address", c.address, "crc", crc, "calculated", crc32.ChecksumIEEE(data[:5]))
		// Safe remove the packet from buffer when we don't believe to n
		copy(c.buf[c.bufOffset:], c.buf[c.bufOffset+(c.bufSize-lastSize):c.bufSize])
		c.bufSize = lastSize

		c.bufLock.Unlock()
		return nil, errors.New("invalid CRC32")
	}
	n := int(data[0])<<8 | int(data[1])
	if n <= 0 || n+ADDSIZE > BUFSIZE {
		// Safe remove the packet from buffer when we don't believe to n
		copy(c.buf[c.bufOffset:], c.buf[c.bufOffset+(c.bufSize-lastSize):c.bufSize])
		c.bufSize = lastSize

		c.bufLock.Unlock()
		return nil, errors.New("invalid message size")
	}

	logger.Debug("client ReadBuf size", "address", c.address.String(), "n", n)
	if n+ADDSIZE > c.bufSize-c.bufOffset {
		c.bufLock.Unlock()
		logger.Error("client Readbuf: incomplete message", "address", c.address.String(), "needed", n+ADDSIZE, "have", c.bufSize-c.bufOffset)
		//return nil, errors.New("incomplete message")
		return c.ReadBuf()
	}
	seq := int(data[2])<<8 | int(data[3])
	flags := Cmd(data[4])

	logger.Debug("client ReadBuf seq", "address", c.address, "seq", seq, "expected", c.seqIn)
	// Sanity check of "n"
	if n <= 0 || n+ADDSIZE > BUFSIZE {
		c.removeThePacketFromBuffer(n)

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
	if c.seqIn > 65535 {
		c.seqIn = 0
	}

	if flags != NoneCmd && flags != NoEncryptionCmd {
		logger.Debug("client ReadBuf process command", "address", c.address.String(), "flags", flags)
		return c.processCommand(flags, data, n)
	}

	msg := make([]byte, n+ADDSIZE)
	copy(msg, c.buf[c.bufOffset:c.bufOffset+n+ADDSIZE])

	/* Remove the packet from buffer */
	c.removeThePacketFromBuffer(n)
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

	// Check signature for the packet
	if !c.secrets.Verify(msg[:HEADER+n], msg[HEADER+n:HEADER+n+crypt.SIGNLEN]) {
		logger.Error("client Readbuf: invalid signature. The packet is dropped", "address", c.address.String())

		return nil, errors.New("invalid signature")
	}

	// decrypt the packet
	/*
		if flags != NoEncryptionCmd {
			data, err := c.secrets.CryptDecrypt(msg[:HEADER+n])
			if err != nil {
				logger.Error("client Readbuf: decrypt error", "address", c.address.String(), "error", err)
				return nil, err
			}
			copy(msg, data)
		}*/

	return msg[HEADER : HEADER+n], nil
}

func (c *Client) Write(msg *transport.Message, cmd Cmd) error {
	c.orderSendLock.Lock()
	defer c.orderSendLock.Unlock()

	n := len(*msg)
	logger.Debug("client Write data", "len", n, "address", c.address.String())

	if n+ADDSIZE > BUFSIZE {
		return errors.New("invalid message size")
	}
	buf := make([]byte, n+ADDSIZE)
	buf[0] = byte(n >> 8)
	buf[1] = byte(n & 0xff)
	c.seqOutLock.Lock()
	buf[2] = byte(c.seqOut >> 8)
	buf[3] = byte(c.seqOut & 0xff)
	seq := c.seqOut
	c.seqOut++
	if c.seqOut > 65535 {
		c.seqOut = 0
	}
	c.seqOutLock.Unlock()
	buf[4] = byte(cmd) // flags or command

	crc := crc32.ChecksumIEEE(buf[:5])
	buf[5] = byte(crc >> 24)
	buf[6] = byte((crc >> 16) & 0xff)
	buf[7] = byte((crc >> 8) & 0xff)
	buf[8] = byte(crc & 0xff)
	// Copy message
	logger.Debug("client Write", "address", c.address, "seq", seq)
	// Encrypt the message
	copy(buf[HEADER:n+HEADER], *msg)
	/*
		if cmd != NoEncryptionCmd {
			data, err := c.secrets.CryptDecrypt(buf[HEADER : HEADER+n])
			if err != nil {
				return err
			}
			copy(buf[HEADER:HEADER+n], data)
		}*/

	signature := c.secrets.Sign(buf[:HEADER+n])
	copy(buf[HEADER+n:], signature)
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
