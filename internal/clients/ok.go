package clients

import (
	"bytes"
	"errors"
	//lint:ignore ST1001 reason: it's safer to use . import here to avoid name conflicts
	. "github.com/sem-hub/snake-net/internal/interfaces"
)

func SendOKMessage(c *Client) error {
	buf := []byte{'O', 'K'}
	if err := c.Write(&buf, WithPadding); err != nil {
		logger.Error("Failed to write OK message", "error", err)
		return errors.New("Failed to write OK message: " + err.Error())
	}
	return nil
}

func SendErrorMessage(c *Client, buf []byte) error {
	if err := c.Write(&buf, WithPadding); err != nil {
		logger.Error("Failed to write Error message", "error", err)
		return errors.New("Failed to write Error message: " + err.Error())
	}
	return nil
}

func WaitForOKMessage(c *Client) error {
	buf, err := c.ReadBuf(HEADER)
	if err != nil {
		logger.Error("Failed to read OK message", "error", err)
		return errors.New("Failed to read OK message: " + err.Error())
	}
	if len(buf) != 2 || !bytes.Equal(buf, []byte("OK")) {
		logger.Error("Received not OK message", "msg", string(buf))
		return errors.New("Received not OK message: " + string(buf))
	}
	return nil
}
