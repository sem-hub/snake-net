package clients

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"

	"github.com/sem-hub/snake-net/internal/crypt"
	//lint:ignore ST1001 reason: it's safer to use . import here to avoid name conflicts
	"github.com/sem-hub/snake-net/internal/network/transport"
	. "github.com/sem-hub/snake-net/internal/protocol/header"
)

// We send encrypted header (HEADER bytes) + encrypted data + signature of the encrypted data (sign only data, not header)
// If transport is encrypted, we skip header encryption and do not sign (transport cares for all)
// If encryption is AEAD, we do not need to sign (integrity is provided by AEAD)
// cmd contains flags for encryption/signing and commands
func (c *Client) Write(msg *transport.Message, cmd Cmd) error {
	// Do not break packet build. Unless this lock, out of order packets are very likely to happen, which is worse than a bit of delay.
	c.orderSendLock.Lock()
	defer c.orderSendLock.Unlock()

	if c.t.IsEncrypted() {
		// Transport does low-level encryption, so we can skip it
		cmd |= NoEncryption
		cmd |= NoSignature
	}

	// It's possible we have msg == nil. It means we only want to send a command without data. Padding will be added to these packets.
	n := 0
	if msg == nil {
		c.logger.Debug("client Write: no data. Send a command only", "address", c.address.String())
		cmd |= WithPadding
	} else {
		n = len(*msg)
		c.logger.Debug("client Write data", "len", n, "address", c.address.String())

		addLen := 0
		if c.secrets.SignatureEngine != nil && (cmd&NoSignature) == 0 {
			addLen = int(c.secrets.SignatureEngine.SignLen())
		}
		if HEADER+n+addLen > BUFSIZE {
			return errors.New("invalid message size")
		}
	}
	// Copy message
	c.logger.Debug("client Write", "address", c.address, "seq", c.seqOut.Load())

	msgBuf := make([]byte, 0)
	if msg != nil {
		msgBuf = append(msgBuf, *msg...)
	}
	// Need padding
	if (cmd & WithPadding) != 0 {
		msgBuf = crypt.Pad(msgBuf)
	}

	buf := make([]byte, HEADER)

	var err error
	if c.secrets.Engine != nil || (cmd&NoEncryption) == 0 {
		msgBuf, err = c.secrets.SignAndEncrypt(msgBuf, cmd)
		if err != nil {
			c.logger.Error("client Write SignAndEncrypt error", "error", err, "address", c.address, "seq", c.seqOut.Load())
			return err
		}
	}
	buf = append(buf, msgBuf...)

	n = len(buf) - HEADER
	seq := c.seqOut.Load()
	c.seqOut.Add(1)

	headerBuf := new(bytes.Buffer)
	err = binary.Write(headerBuf, binary.BigEndian, uint16(n))
	if err != nil {
		c.logger.Error("client Write binary.Write error", "error", err, "address", c.address, "seq", seq)
		return err
	}
	err = binary.Write(headerBuf, binary.BigEndian, uint16(seq))
	if err != nil {
		c.logger.Error("client Write binary.Write error", "error", err, "address", c.address, "seq", seq)
		return err
	}
	headerBuf.WriteByte(byte(cmd)) // flags or/and command

	crc := crc32.ChecksumIEEE(headerBuf.Bytes()[:5])
	c.logger.Debug("client Write", "crc", crc)
	err = binary.Write(headerBuf, binary.BigEndian, crc)
	if err != nil {
		c.logger.Error("client Write binary.Write error", "error", err, "address", c.address, "seq", seq)
		return err
	}

	// Encrypt header if transport is not Encrypted. Must not change message size!
	if !c.t.IsEncrypted() {
		encryptData, err := c.secrets.EncryptDecryptNoIV(headerBuf.Bytes())
		if err != nil {
			return err
		}
		copy(buf[:HEADER], encryptData)
	} else {
		copy(buf[:HEADER], headerBuf.Bytes())
	}

	c.logger.Debug("client Write final", "address", c.address, "n", n, "bufsize", len(buf))
	err = c.t.Send(c.address, &buf)
	if err != nil {
		c.logger.Error("client Write send error", "error", err, "address", c.address, "seq", seq)
		return err
	}
	c.logger.Debug("client Write sent", "len", len(buf), "address", c.address.String(), "seq", seq)
	c.sentBuffer.Push(buf)
	return nil
}
