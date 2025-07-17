package protocol

import (
	"bytes"
	"errors"
	"net"

	"github.com/sem-hub/snake-net/internal/clients"
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

func ProcessNewClient(t transport.Transport, conn net.Conn, gotAddr net.Addr, tun *water.Interface) {
	logger := configs.GetLogger()

	addr := conn.RemoteAddr()
	if addr == nil {
		addr = gotAddr
	}
	clients.AddClient(conn, addr)
	c := crypt.NewSecrets(addr, t, conn)

	if IdentifyClient(c) {
		logger.Debug("Identification passed")
	} else {
		logger.Debug("Identification failed")
		return
	}

	clients.SetClientState(addr, clients.Authenticated)

	if err := c.ECDH(); err != nil {
		logger.Error("ECDH", "error", err)
	}

	clients.SetClientState(addr, clients.Ready)
	//fmt.Println("Session public key: ", c.GetPublicKey())
	network.ProcessTun(c, tun)
}

func ProcessServer(t transport.Transport, conn net.Conn, addr net.Addr, tun *water.Interface) {
	logger := configs.GetLogger()
	if conn == nil {
		return
	}
	// Well, really it's server but we call it client here
	clients.AddClient(conn, addr)
	c := crypt.NewSecrets(addr, t, conn)
	if err := Identification(c); err != nil {
		logger.Debug("Identification Success")
	} else {
		logger.Debug("Identification Fails")
		return
	}

	clients.SetClientState(addr, clients.Authenticated)

	if err := c.ECDH(); err != nil {
		logger.Error("ECDH", "error", err)
	}
	clients.SetClientState(addr, clients.Ready)

	//fmt.Println("Session public key: ", c.GetPublicKey())
	network.ProcessTun(c, tun)
}
