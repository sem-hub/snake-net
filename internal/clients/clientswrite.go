package clients

import (
	"errors"
	"hash/crc32"

	"github.com/sem-hub/snake-net/internal/network/transport"
)

// We send encrypted header (HEADER bytes) + encrypted data + signature of the encrypted data (not header here)
func (c *Client) Write(msg *transport.Message, cmd Cmd) error {
	c.orderSendLock.Lock()
	defer c.orderSendLock.Unlock()

	var n int = 0
	if msg == nil {
		c.logger.Debug("client Write: no data. Send a command only", "address", c.address.String())
	} else {
		n = len(*msg)
		c.logger.Debug("client Write data", "len", n, "address", c.address.String())

		if HEADER+n+c.secrets.MinimalSize() > BUFSIZE {
			return errors.New("invalid message size")
		}
	}
	// Copy message
	c.logger.Debug("client Write", "address", c.address, "seq", c.seqOut.Load())

	buf := make([]byte, HEADER)

	if msg != nil {
		if (cmd & NoEncryption) == 0 {
			c.logger.Debug("client Write encrypting and sign", "address", c.address, "seq", c.seqOut.Load())
			data, err := c.secrets.EncryptAndSeal(*msg)
			if err != nil {
				return err
			}
			buf = append(buf, data...)
		} else {
			c.logger.Debug("client Write sign only", "address", c.address, "seq", c.seqOut.Load())
			buf = append(buf, *msg...)
			signature := c.secrets.Sign(*msg)
			buf = append(buf, signature...)
		}
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

	encryptData, err := c.secrets.CryptDecrypt(data)
	if err != nil {
		return err
	}
	copy(buf[:HEADER], encryptData)

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
