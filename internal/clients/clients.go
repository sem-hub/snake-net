package clients

import (
	"hash/crc32"
	"log/slog"
	"math/rand"
	"net"
	"net/netip"
	"sync"
	"time"

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

const (
	NoneCmd         Cmd = iota
	AskForResendCmd     = 0xfe
	ShutdownCmd         = 0xff
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

// Executed under lock
func (c *Client) processOOOP(n int, seq int) (transport.Message, error) {
	if seq > c.seqIn {
		if c.lookInBufferForSeq(c.seqIn) {
			// Found in buffer, process it
			logger.Debug("client ReadBuf: found out of order packet in buffer", "address", c.address.String(), "seq", c.seqIn)
			c.bufLock.Unlock()
			return c.ReadBuf()
		}
		// Did not find any packet in buffer. We lost it. Ask for resend.
		seq = c.seqIn
		// Ask for resend only once. XXX We don't process massive lost.
		if c.oooPackets == 1 || c.oooPackets == 5 || c.oooPackets == 10 {
			c.bufLock.Unlock()
			err := c.AskForResend(seq)
			if err != nil {
				logger.Error("OOOP processing: Error when ask a packet for retransmittion", "error", err)
			}
			c.oooPackets++
			return c.ReadBuf()
		}
		// OutOfOrder leave packet in buffer and restart reading
		c.oooPackets++
		if c.oooPackets > 30 {
			// Too many out of order packets, reset buffer
			logger.Error("client ReadBuf: too many out of order packets, ignore the sequence number", "oooPackets", c.oooPackets, "address", c.address.String())
			c.seqIn++
			if c.seqIn > 65535 {
				c.seqIn = 0
			}
			c.bufLock.Unlock()
			return nil, errors.New("too many out of order packets")
		}
		// Go to next packet. Leave the packet in buffer.
		c.bufOffset += n + ADDSIZE
	} else {
		logger.Error("client ReadBuf: duplicate. Drop.")
		c.removeThePacketFromBuffer(n)
	}
	c.bufLock.Unlock()
	return c.ReadBuf()
}

func (c *Client) processCommand(flags Cmd, data []byte, n int) (transport.Message, error) {
	if flags == ShutdownCmd {
		logger.Debug("client ReadBuf shutdown command, closing connection", "address", c.address.String())
		c.bufLock.Unlock()
		c.SetClientState(NotFound)
		c.Close()
		time.Sleep(5 * time.Second)
		RemoveClient(c.address)

		return nil, errors.New("connection closed by peer")
	}
	if flags == AskForResendCmd {
		// Find in sentBuffer and resend
		askSeq := int(data[HEADER])<<8 | int(data[HEADER+1])
		logger.Debug("client ReadBuf asked for resend command", "address", c.address.String(), "seq", askSeq)

		dataSend, ok := c.sentBuffer.Find(func(index interface{}) bool {
			buf := index.([]byte)
			seqNum := int(buf[2])<<8 | int(buf[3])
			return seqNum == askSeq
		})
		if ok {
			buf := dataSend.([]byte)
			seqNum := int(buf[2])<<8 | int(buf[3])
			logger.Debug("client ReadBuf resend for", "address", c.address.String(), "seq", seqNum)
			err := c.t.Send(c.address, &buf)
			if err != nil {
				logger.Error("client ReadBuf resend failed", "address", c.address.String(), "seq", askSeq, "error", err)
			}
			// Hold on the client a little
			time.Sleep(10 * time.Millisecond)
		} else {
			logger.Error("client ReadBuf resend: packet not found in sentBuffer", "address", c.address.String(), "seq", askSeq)
		}
		// Remove the packet from buffer
		c.removeThePacketFromBuffer(n)

		c.bufLock.Unlock()
		return c.ReadBuf()
	}
	return nil, errors.New("unknown command")
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
	/*data, err := c.secrets.CryptDecrypt(c.buf[c.bufOffset : c.bufOffset+HEADER])
	if err != nil {
		c.bufLock.Unlock()
		return nil, err
	}*/
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
	if !c.secrets.Verify(c.buf[c.bufOffset:c.bufOffset+HEADER+n], c.buf[c.bufOffset+HEADER+n:c.bufOffset+n+ADDSIZE]) {
		logger.Error("cleint Readbuf: invalid signature")
		// Drop the packet
		c.removeThePacketFromBuffer(n)

		c.bufLock.Unlock()
		return nil, errors.New("invalid signature")
	}
	seq := int(data[2])<<8 | int(data[3])
	flags := Cmd(data[4])

	//logger.Debug("client ReadBuf flags", "address", c.address, "flags", flags)
	logger.Debug("client ReadBuf seq", "address", c.address, "seq", seq, "expected", c.seqIn)
	if n <= 0 || n+ADDSIZE > BUFSIZE {
		c.removeThePacketFromBuffer(n)

		c.bufLock.Unlock()
		return nil, errors.New("invalid message size")
	}
	needResetOffset := false

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

	if flags != NoneCmd {
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
	c.bufLock.Unlock()

	/*data, err = c.secrets.CryptDecrypt(msg[0 : n+HEADER])
	if err != nil {
		c.bufLock.Unlock()
		return nil, err
	}
	copy(msg, data)*/

	return msg[HEADER : n+HEADER], nil
}

func (c *Client) AskForResend(seq int) error {
	logger.Debug("client AskForResend", "address", c.address.String(), "seq", seq, "oooPackets", c.oooPackets)

	buf := make([]byte, 2)
	buf[0] = byte(seq >> 8)
	buf[1] = byte(seq & 0xff)
	return c.Write(&buf, AskForResendCmd)
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
		logger.Debug("client Write send error", "error", err, "address", c.address, "seq", seq)
		return err
	}
	logger.Debug("client Write sent", "len", len(buf), "address", c.address.String(), "seq", seq)
	c.sentBuffer.Push(buf)
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
	return c.Write(&buf, NoneCmd)
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
