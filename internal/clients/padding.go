package clients

import (
	"crypto/rand"
	mrand "math/rand"
)

func makePadding() []byte {
	paddingSize := mrand.Intn(128)
	padding := make([]byte, paddingSize)
	rand.Read(padding)
	return padding
}

func (c *Client) WriteWithXORAndPadding(msg []byte, needXOR bool) error {
	padding := makePadding()
	paddingSize := len(padding)
	buf := make([]byte, len(msg)+paddingSize)
	copy(buf, msg)
	copy(buf[len(msg):], padding)
	if needXOR {
		c.XOR(&buf)
	}
	c.logger.Debug("client WriteWithPadding", "buflen", len(buf), "datalen", len(msg), "paddingSize", paddingSize, "address", c.address)
	return c.Write(&buf, NoEncryption)
}

func (c *Client) XOR(data *[]byte) {
	c.secrets.XOR(data)
}
