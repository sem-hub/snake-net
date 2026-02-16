package clients

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"

	"github.com/sem-hub/snake-net/internal/network/transport"
	//lint:ignore ST1001 reason: it's safer to use . import here to avoid name conflicts
	. "github.com/sem-hub/snake-net/internal/protocol/header"
)

func getCommandName(command Cmd) string {
	switch command & CmdMask {
	case Ping:
		return "Ping"
	case Pong:
		return "Pong"
	case ShutdownRequest:
		return "ShutdownRequest"
	case ShutdownNotify:
		return "ShutdownNotify"
	case AskForResend:
		return "AskForResend"
	default:
		return "UnknownCommand(" + hex.EncodeToString([]byte{byte(command)}) + ")"
	}
}

// Process special commands received from the client
// Executed under bufLock. data excludes header: data + signature (if any)
func (c *Client) processCommand(command Cmd, data []byte, n uint16) (transport.Message, error) {
	c.logger.Debug("processCommand", "command", getCommandName(command), "address", c.address.String(), "dataLen", len(data), "n", n)
	// Remove the packet from buffer if it's not AskForResend. For AskForResend, we need it to get sequence number.
	if command&CmdMask != AskForResend {
		c.removeThePacketFromBuffer(HEADER + int(n))
		c.bufLock.Unlock()

	}
	switch command & CmdMask {
	case Ping:
		c.logger.Debug("received ping command, sending pong", "address", c.address.String())

		err := c.Write(nil, Pong|WithPadding)
		if err != nil {
			c.logger.Error("failed to send pong command", "address", c.address.String(), "error", err)
		}

		return c.ReadBuf(HEADER)
	case Pong:
		c.logger.Debug("received pong command", "address", c.address.String())

		c.pinger.StopPongTimeoutTimer()
		// timer already reseted when data is received in ReadBuf()
		return c.ReadBuf(HEADER)
	case ShutdownRequest:
		c.logger.Info("got shutdown request command, closing connection", "address", c.address.String())

		_ = c.Write(nil, ShutdownNotify|WithPadding)
		time.Sleep(100 * time.Millisecond) // Give some time to send the notify
		c.Close()
		tunIf.Close()

		return nil, errors.New("connection closed by server")

	case ShutdownNotify:
		c.logger.Info("client sent shutdown notify command, closing connection", "address", c.address.String())

		c.SetClientState(NotFound)
		// RemoveClient() calls c.Close()
		RemoveClient(c.address)

		return nil, errors.New("connection closed by client")

	case AskForResend:
		// we did not decrypt the data yet
		dataDecrypted, err := c.secrets.DecryptAndVerify(data, n, command)
		if err != nil {
			c.logger.Error("process command AskForResend: decrypt&verify error", "address", c.address.String(), "error", err)
			return nil, err
		}

		// Find in sentBuffer and resend
		var askSeq uint16
		err = binary.Read(bytes.NewReader(dataDecrypted), binary.BigEndian, &askSeq)
		if err != nil {
			c.logger.Error("process command AskForResend: binary.Read error", "address", c.address.String(), "error", err)
			return nil, err
		}
		c.logger.Info("client asked to resend packet", "address", c.address.String(), "seq", askSeq)

		dataSend, ok := c.sentBuffer.Find(func(index interface{}) bool {
			buf := index.([]byte)
			header, err := c.getHeaderInfo(buf)
			if err != nil {
				c.logger.Error("process command resend: cannot get header info from sentBuffer", "address", c.address.String(), "error", err)
				return false
			}
			return header.Seq == askSeq
		})
		if ok {
			buf := dataSend.([]byte)
			c.logger.Info("client resend for", "address", c.address.String(), "seq", askSeq)
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
		c.removeThePacketFromBuffer(HEADER + int(n))
		c.bufLock.Unlock()
		return c.ReadBuf(HEADER)
	default:
		return nil, errors.New("unknown command: " + hex.EncodeToString([]byte{byte(command)}))
	}
}
