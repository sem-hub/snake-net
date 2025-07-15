package protocol

import (
	"bytes"
	"errors"
	"net"

	"github.com/sem-hub/snake-net/internal/aioread"
	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/crypt"
	"github.com/sem-hub/snake-net/internal/network"
	"github.com/sem-hub/snake-net/internal/network/transport"
	"github.com/songgao/water"
)

func IdentifyClient(c *crypt.Secrets) bool {
	buf, err := c.Read()
	if err != nil {
		return false
	}
	if bytes.Equal(buf, []byte("Hello")) {
		buf = []byte("World")
		c.Write(&buf)
	} else {
		buf = []byte("Error")
		c.Write(&buf)
		return false
	}
	return true
}

func Identification(c *crypt.Secrets) error {
	logger := configs.GetLogger()
	msg := []byte("Hello")
	err := c.Write(&msg)
	if err != nil {
		return err
	}

	msg1, err := c.Read()
	if err != nil {
		return err
	}
	if !bytes.Equal(msg1, []byte("Error")) {
		return errors.New("Identification error")
	}
	logger.Debug("ID", "msg", msg1)
	return nil
}

func ProcessClient(t transport.Transport, conn net.Conn, tun *water.Interface) {
	logger := configs.GetLogger()
	aio := aioread.NewAioRead(t, conn)
	c := crypt.NewSecrets(aio)

	if IdentifyClient(c) {
		logger.Debug("Identification passed")
	} else {
		logger.Debug("Identification failed")
		return
	}

	if err := c.ECDH(); err != nil {
		logger.Error("ECDH", "error", err)
	}
	//fmt.Println("Session public key: ", c.GetPublicKey())
	network.ProcessTun(c, tun)
}

func ProcessServer(t transport.Transport, conn net.Conn, tun *water.Interface) {
	logger := configs.GetLogger()
	aio := aioread.NewAioRead(t, conn)
	c := crypt.NewSecrets(aio)
	if err := Identification(c); err != nil {
		logger.Debug("Identification Success")
	} else {
		logger.Debug("Identification Fails")
		return
	}

	if err := c.ECDH(); err != nil {
		logger.Error("ECDH", "error", err)
	}
	//fmt.Println("Session public key: ", c.GetPublicKey())
	network.ProcessTun(c, tun)
}
