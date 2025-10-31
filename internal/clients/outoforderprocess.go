package clients

import (
	"errors"

	"github.com/sem-hub/snake-net/internal/network/transport"
)

// Process special out-of-order packets received from the client
// Executed under bufLock
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

func (c *Client) AskForResend(seq int) error {
	logger.Debug("client AskForResend", "address", c.address.String(), "seq", seq, "oooPackets", c.oooPackets)

	buf := make([]byte, 2)
	buf[0] = byte(seq >> 8)
	buf[1] = byte(seq & 0xff)
	return c.Write(&buf, AskForResendCmd)
}
