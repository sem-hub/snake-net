package clients

import (
	"errors"
	"time"

	"github.com/sem-hub/snake-net/internal/network/transport"
)

const (
	NoneCmd         Cmd = iota
	NoEncryptionCmd     = 0xfd
	AskForResendCmd     = 0xfe
	ShutdownCmd         = 0xff
)

// Process special commands received from the client
// Executed under bufLock
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
	return nil, errors.New("unknown command: " + string(flags))
}
