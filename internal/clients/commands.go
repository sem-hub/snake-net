package clients

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"

	"github.com/sem-hub/snake-net/internal/crypt"
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

func (c *Client) enqueueResendToMainLoop(buf transport.Message, askSeq uint16, observedSeq uint16) error {
	req := sendRequest{
		buf:              buf,
		seq:              askSeq,
		result:           make(chan error, 1),
		isPriority:       true,
	}

	c.sendQueueLock.Lock()
	select {
	case c.prioSendQueue <- req:
		c.sendQueueLock.Unlock()
		c.logger.Debug("client resend queued", "address", c.address, "seq", askSeq, "observedSeq", observedSeq)
		return nil
	case <-c.sendLoopDone:
		c.sendQueueLock.Unlock()
		return errors.New("client is closed")
	}
}

// Process special commands received from the client
// Executed under bufLock. data excludes header: data + signature (if any)
func (c *Client) processCommand(command Cmd, data []byte, n uint16) (transport.Message, error) {
	c.logger.Debug("processCommand", "command", getCommandName(command), "address", c.address, "dataLen", len(data), "n", n)
	// Remove the packet from buffer if it's not AskForResend. For AskForResend, we need it to get sequence number.
	if command&CmdMask != AskForResend {
		c.removeThePacketFromBuffer(HEADER + int(n))
		c.bufLock.Unlock()

	}
	switch command & CmdMask {
	case Ping:
		c.logger.Debug("received ping command, sending pong", "address", c.address)

		err := c.Write(nil, Pong|WithPadding)
		if err != nil {
			c.logger.Error("failed to send pong command", "address", c.address, "error", err)
		}

		return nil, errReadBufContinue
	case Pong:
		c.logger.Debug("received pong command", "address", c.address)

		c.pinger.StopPongTimeoutTimer()
		// timer already reseted when data is received in ReadBuf()
		return nil, errReadBufContinue
	case ShutdownRequest:
		c.logger.Info("got shutdown request command, closing connection", "address", c.address)

		_ = c.Write(nil, ShutdownNotify|WithPadding)
		time.Sleep(100 * time.Millisecond) // Give some time to send the notify
		c.Close()
		tunIf.Close()

		return nil, errors.New("connection closed by server")

	case ShutdownNotify:
		c.logger.Info("client sent shutdown notify command, closing connection", "address", c.address)

		c.SetClientState(NotFound)
		// RemoveClient() calls c.Close()
		RemoveClient(c.address)

		return nil, errors.New("connection closed by client")

	case AskForResend:
		var dataDecrypted []byte
		var err error

		if !c.t.IsEncrypted() {
			// we did not decrypt the data yet
			dataDecrypted, err = c.secrets.DecryptAndVerify(data, n, command)
			if err != nil {
				c.logger.Error("process command AskForResend: decrypt&verify error", "address", c.address, "error", err)
				return nil, err
			}
		} else {
			dataDecrypted = data[:n]
		}

		if (command & WithPadding) != 0 {
			dataDecrypted, err = crypt.UnPad(dataDecrypted)
			if err != nil {
				c.logger.Error("process command AskForResend: unpadding error", "address", c.address, "error", err)
				return nil, err
			}
		}

		// Find in sentBuffer and resend.
		// Payload format: [askSeq(2)][observedSeq(2)]
		if len(dataDecrypted) != 4 {
			err = errors.New("AskForResend payload must be 4 bytes")
			c.logger.Error("process command AskForResend: invalid payload", "address", c.address, "len", len(dataDecrypted), "error", err)
			return nil, err
		}

		askSeq := binary.BigEndian.Uint16(dataDecrypted[0:2])
		observedSeq := binary.BigEndian.Uint16(dataDecrypted[2:4])
		//c.activateSendThrottling(1 * time.Second)

		c.logger.Warn("client asked to resend packet", "address", c.address, "seq", askSeq, "observedSeq", observedSeq)
		var resendBuf transport.Message
		shouldResend := false

		dataSend, ok := c.sentBuffer.Find(func(index interface{}) bool {
			buf := index.([]byte)
			header, err := c.getHeaderInfo(buf)
			if err != nil {
				c.logger.Error("process command resend: cannot get header info from sentBuffer", "address", c.address, "error", err)
				return false
			}
			return header.Seq == askSeq
		})
		if ok {
			buf := dataSend.([]byte)
			resendBuf = append([]byte(nil), buf...)
			shouldResend = true
			c.logger.Debug("client resend prepared", "address", c.address, "seq", askSeq, "observedSeq", observedSeq)
		} else {
			snapshot := c.sentBuffer.Snapshot()
			minSeq := uint16(0)
			maxSeq := uint16(0)
			hasSeq := false
			invalidPackets := 0

			for _, item := range snapshot {
				buf, ok := item.([]byte)
				if !ok || len(buf) < HEADER {
					invalidPackets++
					continue
				}

				header, err := c.getHeaderInfo(buf)
				if err != nil {
					invalidPackets++
					continue
				}

				if !hasSeq {
					minSeq = header.Seq
					maxSeq = header.Seq
					hasSeq = true
					continue
				}

				if header.Seq < minSeq {
					minSeq = header.Seq
				}
				if header.Seq > maxSeq {
					maxSeq = header.Seq
				}
			}

			if hasSeq {
				c.logger.Error("process command resend: packet not found in sentBuffer",
					"address", c.address,
					"seq", askSeq,
					"observedSeq", observedSeq,
					"bufferCount", len(snapshot),
					"bufferMinSeq", minSeq,
					"bufferMaxSeq", maxSeq,
					"invalidPackets", invalidPackets)
			} else {
				c.logger.Error("process command resend: packet not found in sentBuffer",
					"address", c.address,
					"seq", askSeq,
					"observedSeq", observedSeq,
					"bufferCount", len(snapshot),
					"bufferEmptyOrUnreadable", true,
					"invalidPackets", invalidPackets)
			}
		}
		// Remove the packet from buffer
		c.removeThePacketFromBuffer(HEADER + int(n))
		c.bufLock.Unlock()
		if shouldResend {
			err := c.enqueueResendToMainLoop(resendBuf, askSeq, observedSeq)
			if err != nil {
				c.logger.Error("process command resend enqueue failed", "address", c.address, "seq", askSeq, "error", err)
			}
		}
		return nil, errReadBufContinue
	default:
		return nil, errors.New("unknown command: " + hex.EncodeToString([]byte{byte(command)}))
	}
}
