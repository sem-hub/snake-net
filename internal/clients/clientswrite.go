package clients

import (
	"errors"
	"hash/crc32"

	"github.com/sem-hub/snake-net/internal/crypt"
	"github.com/sem-hub/snake-net/internal/network/transport"
)

// We send encrypted header (HEADER bytes) + encrypted data + signature of the encrypted data (not header here)
func (c *Client) Write(msg *transport.Message, cmd Cmd) error {
	c.orderSendLock.Lock()
	defer c.orderSendLock.Unlock()

	if c.t.IsEncrypted() {
		// Transport does low-level encryption, so we can skip it
		cmd |= NoEncryption
		cmd |= NoSignature
	}

	var n int = 0
	if msg == nil {
		c.logger.Debug("client Write: no data. Send a command only", "address", c.address.String())
		cmd |= WithPadding
	} else {
		n = len(*msg)
		c.logger.Debug("client Write data", "len", n, "address", c.address.String())

		if HEADER+n+crypt.SIGNLEN > BUFSIZE {
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

	// Sign BEFORE encryption
	var signature []byte
	if (cmd & NoSignature) == 0 {
		signature = c.secrets.Sign(msgBuf)
	}

	buf := make([]byte, HEADER)

	if (cmd & NoEncryption) == 0 {
		c.logger.Debug("client Write encrypting and sign", "address", c.address, "seq", c.seqOut.Load())
		data, err := c.secrets.Encrypt(msgBuf)
		if err != nil {
			return err
		}
		buf = append(buf, data...)
	} else {
		buf = append(buf, msgBuf...)
	}

	// Unencrypted signature at the end
	if (cmd & NoSignature) == 0 {
		buf = append(buf, signature...)
	}

	n = len(buf) - HEADER
	seq := c.seqOut.Load()
	c.seqOut.Add(1)

	data := make([]byte, HEADER)
	data[0] = byte(n >> 8)
	data[1] = byte(n & 0xff)
	data[2] = byte(seq >> 8)
	data[3] = byte(seq & 0xff)
	data[4] = byte(cmd) // flags or command

	crc := crc32.ChecksumIEEE(data[:5])
	c.logger.Debug("client Write", "crc", crc)
	data[5] = byte(crc >> 24)
	data[6] = byte((crc >> 16) & 0xff)
	data[7] = byte((crc >> 8) & 0xff)
	data[8] = byte(crc & 0xff)

	// Encrypt header if transport is not Encrypted. Must not change buf size!
	if !c.t.IsEncrypted() {
		encryptData, err := c.secrets.CryptDecrypt(data)
		if err != nil {
			return err
		}
		copy(buf[:HEADER], encryptData)
	} else {
		copy(buf[:HEADER], data)
	}

	c.logger.Debug("client Write final", "address", c.address, "n", n, "bufsize", len(buf))
	err := c.t.Send(c.address, &buf)
	if err != nil {
		c.logger.Error("client Write send error", "error", err, "address", c.address, "seq", seq)
		return err
	}
	c.logger.Debug("client Write sent", "len", len(buf), "address", c.address.String(), "seq", seq)
	c.sentBuffer.Push(buf)
	return nil
}
