package clients

import (
	"errors"
	"hash/crc32"

	"github.com/sem-hub/snake-net/internal/network/transport"
)

// Process special out-of-order packets received from the client
// Executed under bufLock
func (c *Client) processOOOP(n int, seq uint32) (transport.Message, error) {
	if seq > c.seqIn {
		if c.lookInBufferForSeq(c.seqIn) {
			// Found in buffer, process it
			c.logger.Debug("client OOOP: found out of order packet in buffer", "address", c.address.String(), "seq", c.seqIn)
			c.bufLock.Unlock()
			return c.ReadBuf(HEADER)
		}
		// Did not find any packet in buffer. We lost it. Ask for resend.
		seq = c.seqIn
		// Ask for resend only once. XXX We don't process massive lost.
		if c.oooPackets == 1 || c.oooPackets == 5 || c.oooPackets == 10 {
			c.bufLock.Unlock()
			err := c.AskForResend(seq)
			if err != nil {
				c.logger.Error("OOOP processing: Error when ask a packet for retransmittion", "error", err)
			}
			c.oooPackets++
			return c.ReadBuf(HEADER)
		}
		// OutOfOrder leave packet in buffer and restart reading
		c.oooPackets++
		if c.oooPackets > 30 {
			// Too many out of order packets, reset buffer
			c.logger.Error("client ReadBuf: too many out of order packets, ignore the sequence number", "oooPackets", c.oooPackets, "address", c.address.String())
			c.seqIn++
			c.bufLock.Unlock()
			return nil, errors.New("too many out of order packets")
		}
		// Go to next packet. Leave the packet in buffer.
		c.bufOffset += HEADER + n
	} else {
		c.logger.Error("client ReadBuf: duplicate. Drop.")
		c.removeThePacketFromBuffer(HEADER + n)
	}
	c.bufLock.Unlock()
	return c.ReadBuf(HEADER)
}

// Executed under lock
func (c *Client) lookInBufferForSeq(seq uint32) bool {
	offset := 0
	for offset < c.bufSize {
		if c.bufSize-offset < HEADER+c.secrets.MinimalSize() {
			return false
		}
		// header is encrypted, decrypt it first
		dataHeader, err := c.secrets.CryptDecrypt(c.buf[offset : offset+HEADER])
		if err != nil {
			c.bufLock.Unlock()
			c.logger.Error("lookInBufferForSeq: decrypt error", "address", c.address, "error", err)
			// really buf is corrupted
			return false
		}

		crc := uint32(dataHeader[5])<<24 | uint32(dataHeader[6])<<16 | uint32(dataHeader[7])<<8 | uint32(dataHeader[8])
		if crc != crc32.ChecksumIEEE(dataHeader[:5]) {
			c.logger.Error("lookInBufferForSeq CRC32 error", "address", c.address, "offset", offset, "crc", crc,
				"calculated", crc32.ChecksumIEEE(dataHeader[:5]))
			return false
		}
		// Get data size and sequence number
		n := int(dataHeader[0])<<8 | int(dataHeader[1])
		packetSeq := uint32(dataHeader[2])<<8 | uint32(dataHeader[3])
		if packetSeq == seq {
			c.bufOffset = offset
			return true
		}
		offset += HEADER + n
	}
	return false
}

func (c *Client) AskForResend(seq uint32) error {
	c.logger.Debug("client AskForResend", "address", c.address.String(), "seq", seq, "oooPackets", c.oooPackets)

	buf := make([]byte, 2)
	buf[0] = byte(seq >> 8)
	buf[1] = byte(seq & 0xff)
	padding := MakePadding()
	buf = append(buf, padding...)
	return c.Write(&buf, AskForResend)
}
