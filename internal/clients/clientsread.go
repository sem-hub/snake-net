package clients

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"net/netip"
	"strconv"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/crypt"

	//lint:ignore ST1001 reason: it's safer to use . import here to avoid name conflicts
	"github.com/sem-hub/snake-net/internal/network/transport"
	. "github.com/sem-hub/snake-net/internal/protocol/header"
)

func (c *Client) getHeaderInfo(buf []byte) (Header, error) {
	headerWithCRC := HeaderWithCRC{}
	var dataHeader []byte
	if c.t.IsEncrypted() {
		dataHeader = buf
	} else {
		var err error
		dataHeader, err = c.secrets.EncryptDecryptNoIV(buf[:HEADER])
		if err != nil {
			c.logger.Error("getHeaderInfo decrypt error", "address", c.address.String(), "error", err)
			return Header{}, err
		}
	}

	err := binary.Read(bytes.NewReader(dataHeader), binary.BigEndian, &headerWithCRC)
	if err != nil {
		c.logger.Error("getHeaderInfo binary.Read error", "address", c.address.String(), "error", err)
		return Header{}, err
	}

	if headerWithCRC.CRC != crc32.ChecksumIEEE(dataHeader[:5]) {
		c.logger.Error("getHeaderInfo CRC32 error", "address", c.address.String(), "crc", headerWithCRC.CRC, "calculated", crc32.ChecksumIEEE(dataHeader[:5]))
		return Header{}, errors.New("CRC32 mismatch")
	}

	return headerWithCRC.Header, nil
}

// ReadLoop reads data from network into client's buffer
// Send signal to bufSignal when data is available
func (c *Client) TransportReadLoop(address netip.AddrPort) {
	c.logger.Debug("ReadLoop", "address", address)
	// read data from network into c.buf
	// when data is available, send signal to c.bufSignal
	// main loop will read data from c.buf
	go func() {
		for {
			c.logger.Debug("client ReadLoop waiting for data", "address", address.String())
			msg, n, err := c.t.Receive(address)
			if err != nil {
				c.logger.Error("client ReadLoop Receive error", "err", err)
				c.bufSignal.Signal()
				// We got an error. Mostly it will EOF(XXX), so close and remove the client
				c.SetClientState(NotFound)
				RemoveClient(c.address)
				if configs.GetConfig().Mode == "client" {
					if tunIf != nil {
						tunIf.Close()
					}
				}
				break
			}

			// We got some data, reset ping timer
			if c.pinger != nil {
				c.pinger.ResetPingTimer()
			}

			c.bufLock.Lock()
			// Write to the end of the buffer
			c.logger.Debug("client ReadLoop put in buf", "len", n, "bufSize", c.bufSize, "address", address.String())
			copy(c.buf[c.bufSize:], msg[:n])
			c.bufSize += n
			if n > 0 {
				c.bufSignal.Signal()
			}
			c.bufLock.Unlock()
			c.logger.Debug("client ReadLoop put", "len", n, "from", address.String())
		}
		c.logger.Debug("client ReadLoop exits", "address", address.String())
	}()
}

// ReadBuf reads one full message from client's buffer
// reqSize - minimal size to read (usually HEADER size)
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
	header, err := c.getHeaderInfo(c.buf[c.bufOffset : c.bufOffset+HEADER])
	if err != nil {
		c.logger.Error("client ReadBuf: getHeaderInfo error", "address", c.address.String(), "error", err)
		// Safe remove the packet from buffer when we don't believe to n
		c.removeThePacketFromBuffer(c.bufSize - lastSize)
		c.bufSize = lastSize

		c.bufLock.Unlock()
		return nil, err
	}
	c.logger.Debug("client ReadBuf after reading", "address", c.address.String(), "lastSize", lastSize, "bufSize", c.bufSize, "bufOffset", c.bufOffset)

	addSize := 0
	if !c.secrets.SignatureEngine.IsActive() {
		header.Flags |= NoSignature
	}
	if c.secrets.SignatureEngine != nil && (header.Flags&NoSignature) == 0 {
		addSize = int(c.secrets.SignatureEngine.SignLen())
	}
	if int(header.Size) < addSize || HEADER+int(header.Size) > BUFSIZE {
		// Safe remove the packet from buffer when we don't believe to n
		c.removeThePacketFromBuffer(c.bufSize - lastSize)
		c.bufSize = lastSize

		c.bufLock.Unlock()
		return nil, errors.New("invalid message size. addsize: " + strconv.Itoa(int(addSize)))
	}

	c.logger.Debug("client ReadBuf size", "address", c.address.String(), "size", header.Size)
	if HEADER+int(header.Size) > c.bufSize-c.bufOffset {
		c.bufLock.Unlock()
		c.logger.Warn("client Readbuf: incomplete message", "address", c.address.String(), "needed", HEADER+int(header.Size)+addSize, "have", c.bufSize-c.bufOffset)
		//return nil, errors.New("incomplete message")
		return c.ReadBuf(HEADER + int(header.Size))
	}
	// Set flags for NoEncryption and NoSignature if transport already does it
	if c.t.IsEncrypted() {
		header.Flags |= NoEncryption
		header.Flags |= NoSignature
	}

	c.logger.Debug("client ReadBuf seq", "address", c.address, "seq", header.Seq, "expected", c.seqIn)
	// Sanity check of "n"
	if header.Size <= 0 || HEADER+int(header.Size) > BUFSIZE {
		c.removeThePacketFromBuffer(HEADER + int(header.Size))

		c.bufLock.Unlock()
		return nil, errors.New("invalid message size. header size: " + strconv.Itoa(int(header.Size)))
	}
	needResetOffset := false

	// Out of order or lost packets processing
	if header.Seq != c.seqIn {
		c.logger.Error("client ReadBuf: invalid sequence number", "seq", header.Seq,
			"expected", c.seqIn, "address", c.address, "oooPackets", c.oooPackets)
		// We still hold lock here. Unlock inside the function.
		return c.processOOOP(header.Size, header.Seq)
	} else {
		// In order, reset bufOffset and oooPackets counter
		if c.ooopTimer != nil {
			c.ooopTimer.Stop()
			c.ooopTimer = nil
		}
		c.reaskedPackets = 0
		if c.oooPackets > 0 {
			c.oooPackets = 0
			if c.bufOffset != 0 {
				needResetOffset = true
			}
			c.logger.Info("client ReadBuf: restored order", "address", c.address.String(), "seq", header.Seq)
		}
	}
	c.seqIn++

	// msg is a plaing data on finish: no header, no padding etc.
	msg := make([]byte, header.Size)
	copy(msg, c.buf[c.bufOffset+HEADER:c.bufOffset+HEADER+int(header.Size)])

	if (header.Flags & CmdMask) != NoneCmd {
		c.logger.Debug("client ReadBuf process command", "address", c.address.String(), "flags", header.Flags)
		return c.processCommand(header.Flags, msg, header.Size)
	}

	if header.Size == 0 {
		c.logger.Error("Only header in packet and it's not command. Ignore it", "address", c.address.String())
		c.removeThePacketFromBuffer(HEADER)
		return nil, errors.New("plain header and not command. Ignore")
	}

	/* Remove the packet from buffer */
	c.removeThePacketFromBuffer(HEADER + int(header.Size))
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

	if c.secrets.Engine != nil || (header.Flags&NoEncryption) == 0 {
		msg, err = c.secrets.DecryptAndVerify(msg, header.Size, header.Flags)
		if err != nil {
			c.logger.Error("ReadBuf: DecryptAndVerify error", "address", c.address.String())
			return nil, errors.New("decrypt&verify error")
		}
	}

	// Unpad if needed
	if (header.Flags & WithPadding) != 0 {
		msg, err = crypt.UnPad(msg)
		if err != nil {
			c.logger.Error("ReadBuf: UnPadding error")
			return nil, errors.New("unpadding error")
		}
	}

	return msg, nil
}
