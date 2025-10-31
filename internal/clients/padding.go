package clients

import (
	"crypto/rand"
	mrand "math/rand"
)

func (c *Client) WriteWithXORAndPadding(msg []byte, needXOR bool) error {
	paddingSize := mrand.Intn(64)
	buf := make([]byte, len(msg)+paddingSize)
	copy(buf, msg)
	padding := make([]byte, paddingSize)
	rand.Read(padding)
	// 0 byte to separate message and padding
	copy(buf[len(msg):], padding)
	if needXOR {
		c.XOR(&buf)
	}
	logger.Debug("client WriteWithPadding", "buflen", len(buf), "datalen", len(msg), "paddingSize", paddingSize, "address", c.address)
	return c.Write(&buf, NoEncryptionCmd)
}

func (c *Client) XOR(data *[]byte) {
	c.secrets.XOR(data)
}
