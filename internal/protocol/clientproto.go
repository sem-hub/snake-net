package protocol

import (
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/sem-hub/snake-net/internal/clients"
	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/crypt"
	"github.com/sem-hub/snake-net/internal/network"
	"github.com/sem-hub/snake-net/internal/network/transport"
	"github.com/sem-hub/snake-net/internal/utils"
)

func Identification(c *clients.Client) ([]utils.Cidr, error) {
	cidrs := make([]utils.Cidr, 0)

	msg := []byte("Hello")
	for _, addr := range configs.GetConfig().TunAddrs {
		logger.Debug("Adding TUN address to identification", "addr", addr)
		msg = append(msg, ' ')
		prefLen, _ := addr.Network.Mask.Size()
		msg = append(msg, []byte(addr.IP.Unmap().String()+"/"+strconv.Itoa(prefLen))...)
	}
	msg = append(msg, '\x00')

	logger.Debug("Identification", "msg", string(msg))
	err := c.WriteWithXORAndPadding(msg, true)
	if err != nil {
		return nil, err
	}

	msg1, err := c.ReadBuf(1)
	if err != nil {
		return nil, err
	}
	c.XOR(&msg1)
	logger.Debug("ID", "msg", string(msg1))
	eol := strings.Index(string(msg1), "\x00")
	str := strings.Fields(string(msg1[:eol]))
	if len(str) == 0 {
		return nil, errors.New("invalid welcome string")
	}
	if str[0] == "Welcome" {
		for _, addr := range str[1:] {
			logger.Debug("Server IPs", "addr", addr)
			ip, err := netip.ParseAddr(addr)
			if err != nil {
				// XXX send not OK to server
				logger.Error("nvalid IP from welcome string", "addr", addr)
				return nil, errors.New("invalid IP from welcome string: " + addr)
			}
			cidrs = append(cidrs, utils.Cidr{IP: ip, Network: &net.IPNet{}})
		}
	} else {
		return nil, errors.New("Identification " + string(msg1))
	}
	if err := c.WriteWithXORAndPadding([]byte("OK"), true); err != nil {
		logger.Error("Failed to write OK message", "error", err)
		return nil, err
	}
	return cidrs, nil
}

func ProcessServer(t transport.Transport, addr netip.AddrPort) {
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

	buf, err := c.ReadBuf(1)
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

	serverIPs, err := Identification(c)
	if err != nil {
		logger.Debug("Identification Fails", "error", err)
		clients.RemoveClient(addr)
		return
	}
	logger.Debug("Identification Success")

	c.AddTunAddressesToClient(serverIPs)

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

	c.RunReadLoop("client")
	network.ProcessTun()
}
