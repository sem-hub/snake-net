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
		c.logger.Debug("client ReadBuf shutdown command, closing connection", "address", c.address.String())
		c.bufLock.Unlock()
		c.SetClientState(NotFound)
		c.Close()
		time.Sleep(5 * time.Second)
		RemoveClient(c.address)

		return nil, errors.New("connection closed by peer")
	}
	if flags == AskForResendCmd {
		dataDecrypted, err := c.secrets.DecryptAndVerify(data[HEADER : HEADER+n])
		if err != nil {
			c.logger.Error("client Readbuf: decrypt&verify error", "address", c.address.String(), "error", err)
			return nil, err
		}
		// Find in sentBuffer and resend
		askSeq := uint32(dataDecrypted[0])<<8 | uint32(dataDecrypted[1])
		c.logger.Debug("client ReadBuf asked for resend command", "address", c.address.String(), "seq", askSeq)

		dataSend, ok := c.sentBuffer.Find(func(index interface{}) bool {
			buf := index.([]byte)
			seqNum := uint32(buf[2])<<8 | uint32(buf[3])
			return seqNum == askSeq
		})
		if ok {
			buf := dataSend.([]byte)
			seqNum := uint32(buf[2])<<8 | uint32(buf[3])
			c.logger.Debug("client ReadBuf resend for", "address", c.address.String(), "seq", seqNum)
			err := c.t.Send(c.address, &buf)
			if err != nil {
				c.logger.Error("client ReadBuf resend failed", "address", c.address.String(), "seq", askSeq, "error", err)
			}
			// Hold on the client a little
			time.Sleep(10 * time.Millisecond)
		} else {
			c.logger.Error("client ReadBuf resend: packet not found in sentBuffer", "address", c.address.String(), "seq", askSeq)
		}
		// Remove the packet from buffer
		c.removeThePacketFromBuffer(HEADER + n)

		c.bufLock.Unlock()
		return c.ReadBuf(1)
	}
	return nil, errors.New("unknown command: " + string(flags))
}
