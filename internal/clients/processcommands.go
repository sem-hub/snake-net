package clients

import (
	"errors"
	"time"

	"github.com/sem-hub/snake-net/internal/network/transport"
)

const (
	NoneCmd         Cmd = iota
	ShutdownNotify      = 0xfc
	NoEncryptionCmd     = 0xfd
	AskForResendCmd     = 0xfe
	ShutdownRequest     = 0xff
)

// Process special commands received from the client
// Executed under bufLock
func (c *Client) processCommand(flags Cmd, data []byte, n int) (transport.Message, error) {
	switch flags {
	case ShutdownRequest:
		c.removeThePacketFromBuffer(HEADER)
		c.bufLock.Unlock()
		c.logger.Info("got shutdown request command, closing connection", "address", c.address.String())

		c.Write(nil, ShutdownNotify)
		c.Close()

		return nil, errors.New("connection closed by server")

	case ShutdownNotify:
		c.removeThePacketFromBuffer(HEADER)
		c.bufLock.Unlock()
		c.logger.Info("client sent shutdown notify command, closing connection", "address", c.address.String())

		c.SetClientState(NotFound)
		c.Close()
		RemoveClient(c.address)

		return nil, errors.New("connection closed by client")

	case AskForResendCmd:
		dataDecrypted, err := c.secrets.DecryptAndVerify(data[HEADER : HEADER+n])
		if err != nil {
			c.logger.Error("process command AskForResendCmd: decrypt&verify error", "address", c.address.String(), "error", err)
			return nil, err
		}
		// Find in sentBuffer and resend
		askSeq := uint32(dataDecrypted[0])<<8 | uint32(dataDecrypted[1])
		c.logger.Debug("client asked for resend command", "address", c.address.String(), "seq", askSeq)

		dataSend, ok := c.sentBuffer.Find(func(index interface{}) bool {
			buf := index.([]byte)
			seqNum := uint32(buf[2])<<8 | uint32(buf[3])
			return seqNum == askSeq
		})
		if ok {
			buf := dataSend.([]byte)
			seqNum := uint32(buf[2])<<8 | uint32(buf[3])
			c.logger.Debug("client resend for", "address", c.address.String(), "seq", seqNum)
			err := c.t.Send(c.address, &buf)
			if err != nil {
				c.logger.Error("process command resend failed", "address", c.address.String(), "seq", askSeq, "error", err)
			}
			// Hold on the client a little
			time.Sleep(5 * time.Millisecond)
		} else {
			c.logger.Error("process command resend: packet not found in sentBuffer", "address", c.address.String(), "seq", askSeq)
		}
		// Remove the packet from buffer
		c.removeThePacketFromBuffer(HEADER + n)

		c.bufLock.Unlock()
		return c.ReadBuf(HEADER)
	default:
		c.removeThePacketFromBuffer(HEADER + n)
		c.bufLock.Unlock()

		return nil, errors.New("unknown command: " + string(flags))
	}
}
