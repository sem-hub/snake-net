package protocol

import (
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

	msg := []byte("Hello " + configs.GetConfig().ClientId)

	for _, addr := range configs.GetConfig().TunAddrs {
		logger.Debug("Adding TUN address to identification", "addr", addr)
		msg = append(msg, ' ')
		prefLen, _ := addr.Network.Mask.Size()
		msg = append(msg, []byte(addr.IP.Unmap().String()+"/"+strconv.Itoa(prefLen))...)
	}
	msg = append(msg, '\x00')
	padding := clients.MakePadding()
	logger.Debug("Identification", "msg", string(msg))
	msg = append(msg, padding...)
	err := c.Write(&msg, clients.NoneCmd)
	if err != nil {
		return nil, err
	}

	msg1, err := c.ReadBuf(clients.HEADER)
	if err != nil {
		return nil, err
	}
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
				logger.Error("invalid IP from welcome string", "addr", addr)
				return nil, errors.New("invalid IP from welcome string: " + addr)
			}
			cidrs = append(cidrs, utils.Cidr{IP: ip, Network: &net.IPNet{}})
		}
	} else {
		return nil, errors.New("Identification " + string(msg1[:eol]))
	}
	buf := []byte{'O', 'K'}
	buf = append(buf, clients.MakePadding()...)
	if err := c.Write(&buf, clients.NoneCmd); err != nil {
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

	serverIPs, err := Identification(c)
	if err != nil {
		logger.Error("Identification Fails", "error", err)
		clients.RemoveClient(addr)
		return
	}
	logger.Info("Identification Success")

	c.AddTunAddressesToClient(serverIPs)

	c.SetClientState(clients.Authenticated)

	if err := c.ECDH(); err != nil {
		logger.Error("ECDH", "error", err)
		clients.RemoveClient(addr)
		return
	}

	buf := []byte{'O', 'K'}
	buf = append(buf, clients.MakePadding()...)
	if err := c.Write(&buf, clients.NoneCmd); err != nil {
		logger.Error("Failed to write OK message", "error", err)
		clients.RemoveClient(addr)
		return
	}

	c.SetClientState(clients.Ready)

	c.RunReadLoop("client")
	c.CreatePinger()
	logger.Info("client started", "address", addr.String())
	network.ProcessTun()
	logger.Debug("client finished")
}
