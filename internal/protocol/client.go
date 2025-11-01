package protocol

import (
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"

	"github.com/sem-hub/snake-net/internal/clients"
	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/crypt"
	"github.com/sem-hub/snake-net/internal/network"
	"github.com/sem-hub/snake-net/internal/network/transport"
)

func Identification(c *clients.Client) error {
	logger := configs.GetLogger()
	msg := []byte("Hello " + configs.GetConfig().TunAddr + " " + configs.GetConfig().TunAddr6 + "\x00")
	logger.Debug("Identification", "msg", string(msg))
	err := c.WriteWithXORAndPadding(msg, true)
	if err != nil {
		return err
	}

	msg1, err := c.ReadBuf()
	if err != nil {
		return err
	}
	c.XOR(&msg1)
	logger.Debug("ID", "msg", string(msg1))
	if !strings.HasPrefix(string(msg1), "Welcome") {
		return errors.New("Identification " + string(msg1))
	}
	if err := c.WriteWithXORAndPadding([]byte("OK"), true); err != nil {
		logger.Debug("Failed to write OK message", "error", err)
		return err
	}
	return nil
}

func ProcessServer(t transport.Transport, address string, port string) {
	logger := configs.GetLogger()
	addr := netip.MustParseAddrPort(address + ":" + port)
	// Well, really it's server but we call it client here
	c := clients.NewClient(addr, t)
	s := crypt.NewSecrets()
	c.AddSecretsToClient(s)

	c.RunNetLoop(addr)

	// Send XOR key to server
	logger.Debug("ProcessServer: Send XOR key", "XORKey", hex.EncodeToString(s.XORKey))
	err := c.WriteWithXORAndPadding(s.XORKey, false)
	if err != nil {
		logger.Debug("Failed to write XOR key", "error", err)
		clients.RemoveClient(addr)
		return
	}

	buf, err := c.ReadBuf()
	if err != nil {
		logger.Debug("Failed to read response message", "error", err)
		clients.RemoveClient(addr)
		return
	}

	c.XOR(&buf)
	if len(buf) < 2 || string(buf[:2]) != "OK" {
		logger.Debug("Invalid server response", "len", len(buf), "msg", string(buf))
		clients.RemoveClient(addr)
		return
	}

	if err := Identification(c); err == nil {
		logger.Debug("Identification Success")
	} else {
		logger.Debug("Identification Fails", "error", err)
		clients.RemoveClient(addr)
		return
	}

	c.SetClientState(clients.Authenticated)

	if err := c.ECDH(); err != nil {
		logger.Error("ECDH", "error", err)
		clients.RemoveClient(addr)
		return
	}

	if err := c.WriteWithXORAndPadding([]byte("OK"), true); err != nil {
		logger.Debug("Failed to write OK message", "error", err)
		clients.RemoveClient(addr)
		return
	}

	c.SetClientState(clients.Ready)

	//fmt.Println("Session public key: ", c.GetPublicKey())
	network.ProcessTun("client", c)
}
