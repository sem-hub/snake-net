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

// reqSize - minimal size to read
func (c *Client) ReadBuf(reqSize int) (transport.Message, error) {
	c.logger.Debug("client ReadBuf", "address", c.address.String(), "bufSize", c.bufSize, "bufOffset", c.bufOffset,
		"reqSize", reqSize)
	// If we need to wait for data
	c.bufLock.Lock()
	var lastSize int = 0
	for c.bufSize-c.bufOffset < reqSize {
		if c.closed {
			c.bufLock.Unlock()
			return nil, errors.New("client is closed")
		}
		lastSize = c.bufSize
		c.bufSignal.Wait()
	}
	// First 2 bytes are size
	// Next 2 bytes are sequence number
	// Next 1 byte is flags
	// Next 4 bytes are CRC32 of the header (of 5 bytes)
	// Next n bytes are message finished with 64 bytes signature
	c.logger.Debug("client ReadBuf after reading", "address", c.address.String(), "lastSize", lastSize, "bufSize", c.bufSize, "bufOffset", c.bufOffset)

	data := make([]byte, c.bufSize-c.bufOffset)
	copy(data, c.buf[c.bufOffset:c.bufSize])
	dataHeader, err := c.secrets.CryptDecrypt(data[:HEADER])
	if err != nil {
		c.bufLock.Unlock()
		return nil, err
	}

	crc := uint32(dataHeader[5])<<24 | uint32(dataHeader[6])<<16 | uint32(dataHeader[7])<<8 | uint32(dataHeader[8])
	if crc != crc32.ChecksumIEEE(dataHeader[:5]) {
		c.logger.Error("ReadBuf CRC32 error", "address", c.address, "crc", crc, "calculated", crc32.ChecksumIEEE(dataHeader[:5]))
		// Safe remove the packet from buffer when we don't believe to n
		copy(c.buf[c.bufOffset:], c.buf[c.bufOffset+(c.bufSize-lastSize):c.bufSize])
		c.bufSize = lastSize

		c.bufLock.Unlock()
		return nil, errors.New("CRC32 error")
	}
	n := int(dataHeader[0])<<8 | int(dataHeader[1])
	if n <= 0 || HEADER+n > BUFSIZE {
		// Safe remove the packet from buffer when we don't believe to n
		copy(c.buf[c.bufOffset:], c.buf[c.bufOffset+(c.bufSize-lastSize):c.bufSize])
		c.bufSize = lastSize

		c.bufLock.Unlock()
		return nil, errors.New("invalid message size")
	}

	c.logger.Debug("client ReadBuf size", "address", c.address.String(), "n", n)
	if HEADER+n > c.bufSize-c.bufOffset {
		c.bufLock.Unlock()
		c.logger.Error("client Readbuf: incomplete message", "address", c.address.String(), "needed", HEADER+n, "have", c.bufSize-c.bufOffset)
		//return nil, errors.New("incomplete message")
		return c.ReadBuf(HEADER + n)
	}
	seq := uint32(dataHeader[2])<<8 | uint32(dataHeader[3])
	flags := Cmd(dataHeader[4])

	c.logger.Debug("client ReadBuf seq", "address", c.address, "seq", seq, "expected", c.seqIn)
	// Sanity check of "n"
	if n <= 0 || HEADER+n > BUFSIZE {
		c.removeThePacketFromBuffer(HEADER + n)

		c.bufLock.Unlock()
		return nil, errors.New("invalid message size")
	}
	needResetOffset := false

	// Out of order or lost packets processing
	if seq != c.seqIn {
		c.logger.Error("client ReadBuf: invalid sequence number", "seq", seq,
			"expected", c.seqIn, "address", c.address, "oooPackets", c.oooPackets)
		// We still hold lock here. Unlock inside the function.
		return c.processOOOP(n, seq)
	} else {
		// In order, reset bufOffset and oooPackets counter
		if c.oooPackets > 0 {
			c.oooPackets = 0
			if c.bufOffset != 0 {
				needResetOffset = true
			}
			c.logger.Info("client ReadBuf: restored order", "address", c.address.String(), "seq", seq)
		}
	}
	c.seqIn++

	if (flags & CmdMask) != NoneCmd {
		c.logger.Debug("client ReadBuf process command", "address", c.address.String(), "flags", flags)
		return c.processCommand(flags&CmdMask, data, n)
	}

	if n == 0 {
		c.logger.Error("Only header in packet and it's not command. Ignore it", "address", c.address.String())
		c.removeThePacketFromBuffer(HEADER)
		return nil, errors.New("plain header and not command. Ignore")
	}

	msg := make([]byte, HEADER+n)
	copy(msg, c.buf[c.bufOffset:c.bufOffset+HEADER+n])

	/* Remove the packet from buffer */
	c.removeThePacketFromBuffer(HEADER + n)
	if needResetOffset {
		c.logger.Debug("client ReadBuf: reset bufOffset to 0", "address", c.address.String())
		c.bufOffset = 0
	}
	if c.bufSize < 0 {
		c.logger.Error("client ReadBuf: ", "address", c.address.String(), "bufSize", c.bufSize)
		c.bufSize = 0
		return nil, errors.New("bad buffer size (<0)")
	}
	// Finished working with buf, unlock
	c.bufLock.Unlock()

	// decrypt and verify the packet or just verify if NoEncryptionCmd flag set
	if (flags & NoEncryption) == 0 {
		c.logger.Debug("client ReadBuf decrypting", "address", c.address.String())
		data, err := c.secrets.DecryptAndVerify(msg[HEADER : HEADER+n])
		if err != nil {
			c.logger.Error("client Readbuf: decrypt&verify error", "address", c.address.String(), "error", err)
			return nil, err
		}
		c.logger.Debug("After decryption", "datalen", len(data), "msglen", len(msg))
		copy(msg[HEADER:], data)
	} else {
		if !c.secrets.Verify(msg[HEADER:HEADER+n-c.secrets.MinimalSize()], msg[HEADER+n-c.secrets.MinimalSize():]) {
			c.logger.Error("client Readbuf: verify error", "address", c.address.String())
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

	var n int = 0
	if msg == nil {
		c.logger.Debug("client Write: no data. Send a command only", "address", c.address.String())
	} else {
		n = len(*msg)
		c.logger.Debug("client Write data", "len", n, "address", c.address.String())

		if HEADER+n+c.secrets.MinimalSize() > BUFSIZE {
			return errors.New("invalid message size")
		}
	}
	// Copy message
	c.logger.Debug("client Write", "address", c.address, "seq", c.seqOut.Load())

	buf := make([]byte, HEADER)

	if msg != nil {
		if (cmd & NoEncryption) == 0 {
			c.logger.Debug("client Write encrypting and sign", "address", c.address, "seq", c.seqOut.Load())
			data, err := c.secrets.EncryptAndSeal(*msg)
			if err != nil {
				return err
			}
			buf = append(buf, data...)
		} else {
			c.logger.Debug("client Write sign only", "address", c.address, "seq", c.seqOut.Load())
			buf = append(buf, *msg...)
			signature := c.secrets.Sign(*msg)
			buf = append(buf, signature...)
		}
	}

	n = len(buf) - HEADER
	seq := c.seqOut.Load()
	c.seqOut.Add(1)

	data := make([]byte, HEADER)
	data[0] = byte(n >> 8)
	data[1] = byte(n & 0xff)
	data[2] = byte(seq >> 8)
	data[3] = byte(seq & 0xff)
	data[4] = byte(cmd) // flags or command

	crc := crc32.ChecksumIEEE(data[:5])
	c.logger.Debug("client Write", "crc", crc)
	data[5] = byte(crc >> 24)
	data[6] = byte((crc >> 16) & 0xff)
	data[7] = byte((crc >> 8) & 0xff)
	data[8] = byte(crc & 0xff)

	encryptData, err := c.secrets.CryptDecrypt(data)
	if err != nil {
		return err
	}
	copy(buf[:HEADER], encryptData)

	c.logger.Debug("client Write final", "address", c.address, "n", n, "bufsize", len(buf))
	err = c.t.Send(c.address, &buf)
	if err != nil {
		c.logger.Error("client Write send error", "error", err, "address", c.address, "seq", seq)
		return err
	}
	c.logger.Debug("client Write sent", "len", len(buf), "address", c.address.String(), "seq", seq)
	c.sentBuffer.Push(buf)
	return nil
}

func (c *Client) Close() error {
	c.closed = true
	err := c.t.CloseClient(c.address)
	if err != nil {
		return err
	}
	return nil
}
