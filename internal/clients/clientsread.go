package clients

import (
	"errors"
	"hash/crc32"

	"github.com/sem-hub/snake-net/internal/network/transport"
)

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
