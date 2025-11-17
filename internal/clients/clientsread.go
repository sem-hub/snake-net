package clients

import (
	"errors"
	"hash/crc32"
	"net/netip"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/crypt"

	//lint:ignore ST1001 reason: it's safer to use . import here to avoid name conflicts
	. "github.com/sem-hub/snake-net/internal/interfaces"
	"github.com/sem-hub/snake-net/internal/network/transport"
)

func (c *Client) getHeaderInfo(buf []byte) (int, uint32, Cmd, error) {
	var dataHeader []byte
	if c.t.IsEncrypted() {
		dataHeader = buf
	} else {
		var err error
		dataHeader, err = c.secrets.CryptDecryptConstSize(buf[:HEADER])
		if err != nil {
			c.logger.Error("getHeaderInfo decrypt error", "address", c.address.String(), "error", err)
			return 0, 0, NoneCmd, err
		}
	}

	crc := uint32(dataHeader[5])<<24 | uint32(dataHeader[6])<<16 | uint32(dataHeader[7])<<8 | uint32(dataHeader[8])
	if crc != crc32.ChecksumIEEE(dataHeader[:5]) {
		c.logger.Error("getHeaderInfo CRC32 error", "address", c.address.String(), "crc", crc, "calculated", crc32.ChecksumIEEE(dataHeader[:5]))
		return 0, 0, NoneCmd, errors.New("CRC32 mismatch")
	}
	n := int(dataHeader[0])<<8 | int(dataHeader[1])
	seq := uint32(dataHeader[2])<<8 | uint32(dataHeader[3])
	flags := Cmd(dataHeader[4])

	return n, seq, flags, nil
}

func (c *Client) ReadLoop(address netip.AddrPort) {
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
	// First 2 bytes are size
	// Next 2 bytes are sequence number
	// Next 1 byte is flags
	// Next 4 bytes are CRC32 of the header (of 5 bytes)
	// Next n bytes are message finished with 64 bytes signature
	n, seq, flags, err := c.getHeaderInfo(c.buf[c.bufOffset : c.bufOffset+HEADER])
	if err != nil {
		c.logger.Error("client ReadBuf: getHeaderInfo error", "address", c.address.String(), "error", err)
		// Safe remove the packet from buffer when we don't believe to n
		copy(c.buf[c.bufOffset:], c.buf[c.bufOffset+(c.bufSize-lastSize):c.bufSize])
		c.bufSize = lastSize

		c.bufLock.Unlock()
		return nil, err
	}
	c.logger.Debug("client ReadBuf after reading", "address", c.address.String(), "lastSize", lastSize, "bufSize", c.bufSize, "bufOffset", c.bufOffset)

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
	// Set flags for NoEncryption and NoSignature if transport does it
	if c.t.IsEncrypted() {
		flags |= NoEncryption
		flags |= NoSignature
	}

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
			c.logger.Info("client ReadBuf: restored order", "address", c.address.String(), "seq", seq)
		}
	}
	c.seqIn++

	// msg is a plaing data on finish: no header, no padding etc.
	msg := make([]byte, n)
	copy(msg, c.buf[c.bufOffset+HEADER:c.bufOffset+HEADER+n])

	if (flags & CmdMask) != NoneCmd {
		c.logger.Debug("client ReadBuf process command", "address", c.address.String(), "flags", flags)
		return c.processCommand(flags, msg, n)
	}

	if n == 0 {
		c.logger.Error("Only header in packet and it's not command. Ignore it", "address", c.address.String())
		c.removeThePacketFromBuffer(HEADER)
		return nil, errors.New("plain header and not command. Ignore")
	}

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

	msg, err = c.secrets.DecryptAndVerify(msg, n, flags)
	if err != nil {
		c.logger.Error("ReadBuf: DecryptAndVerify error", "address", c.address.String())
		return nil, errors.New("decrypt&verify error")
	}

	// Unpad if needed
	if (flags & WithPadding) != 0 {
		msg, err = crypt.UnPad(msg)
		if err != nil {
			c.logger.Error("ReadBuf: UnPadding error")
			return nil, errors.New("unpadding error")
		}
	}

	return msg, nil
}
