package protocol

import (
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strings"

	"github.com/sem-hub/snake-net/internal/clients"
	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/crypt"
	"github.com/sem-hub/snake-net/internal/network"
	"github.com/sem-hub/snake-net/internal/network/transport"
	"github.com/sem-hub/snake-net/internal/utils"
)

func IdentifyClient(c *clients.Client) ([]utils.Cidr, error) {
	logger := configs.GetLogger()
	cidrs := make([]utils.Cidr, 0)

	buf, err := c.ReadBuf()
	if err != nil {
		return nil, err
	}
	if len(buf) < 6 {
		return nil, errors.New("invalid buffer length")
	}
	c.XOR(&buf)
	logger.Debug("IdentifyClient", "ID string", string(buf))
	eol := strings.Index(string(buf), "\x00")
	str := strings.Fields(string(buf[:eol]))
	if len(str) == 0 {
		return nil, errors.New("invalid identification string")
	}
	h := str[0]
	clientCidr := str[1:]
	logger.Debug("IdentifyClient", "h", h, "clientCidrs", clientCidr)
	if h == "Hello" {
		for _, clientNet := range clientCidr {
			logger.Debug("CIDR", "clientNet", clientNet)
			ip, network, err := net.ParseCIDR(clientNet)
			if err != nil {
				logger.Error("Failed to parse CIDR from client", "error", err)
				return nil, err
			}
			logger.Debug("IP from client", "ip", ip)

			for _, cidr := range configs.GetConfig().TunAddrs {
				logger.Debug("Check client IP in server CIDR", "cidr", cidr)
				if cidr.Network.Contains(ip) {
					netIp, _ := netip.AddrFromSlice(ip)
					cidrs = append(cidrs, utils.Cidr{IP: netIp.Unmap(), Network: network})
					logger.Debug("Added CIDR from client", "cidrs", cidrs)
					break
				}
			}
			if len(cidrs) == 0 {
				logger.Error("Client IP not in any server CIDR", "ip", ip.String())
				buf = []byte("Error: IP not in any server CIDR:" + ip.String())
				c.Write(&buf, clients.NoneCmd)

				return nil, errors.New("Client IP " + ip.String() + " not in any server CIDR")
			}
		}
	} else {
		logger.Debug("IdentifyClient: invalid first word", "word", h)
		if err := c.WriteWithXORAndPadding([]byte("Error"), true); err != nil {
			configs.GetLogger().Debug("Failed to write Error message", "error", err)
			return nil, err
		}

		return nil, errors.New("Identification error on first word")
	}

	logger.Debug("IdentifyClient OK", "addr", c.GetClientAddr().String())
	if err := c.WriteWithXORAndPadding([]byte("Welcome"), true); err != nil {
		logger.Debug("Failed to write Welcome message", "error", err)
		return nil, err
	}

	buf, err = c.ReadBuf()
	if err != nil {
		return nil, err
	}
	if len(buf) < 2 {
		return nil, errors.New("invalid buffer length")
	}
	c.XOR(&buf)
	logger.Debug("IdentifyClient", "Final string", string(buf))
	if string(buf[:2]) != "OK" {
		return nil, errors.New("Identification not OK")
	}
	logger.Debug("CIDR from client", "cidrs", cidrs)
	return cidrs, nil
}

func ProcessNewClient(t transport.Transport, addr netip.AddrPort) {
	logger := configs.GetLogger()
	logger.Debug("ProcessNewClient", "gotAddr", addr.String())

	c := clients.NewClient(addr, t)
	s := crypt.NewSecrets()
	c.AddSecretsToClient(s)
	c.RunNetLoop(addr)

	// Get XOR key from client
	buf, err := c.ReadBuf()
	if err != nil {
		logger.Debug("Failed to read XOR key", "error", err)
		clients.RemoveClient(addr)
		return
	}
	if len(buf) < crypt.XORKEYLEN {
		logger.Debug("Invalid XOR key length", "len", len(buf))
		clients.RemoveClient(addr)
		return
	}
	copy(s.XORKey, buf[:crypt.XORKEYLEN])
	logger.Debug("ProcessNewClient: Received XOR key", "XORKey", hex.EncodeToString(s.XORKey))
	if err := c.WriteWithXORAndPadding([]byte("OK"), true); err != nil {
		logger.Debug("Failed to write OK message", "error", err)
		clients.RemoveClient(addr)
		return
	}

	clientTunIPs, err := IdentifyClient(c)
	if err != nil {
		logger.Debug("Identification failed", "error", err)
		if err := c.WriteWithXORAndPadding([]byte("Error"), true); err != nil {
			configs.GetLogger().Debug("Failed to write Error message", "error", err)
		}
		clients.RemoveClient(addr)
		return
	}
	logger.Debug("Identification passed", "clientTunIPs", clientTunIPs)
	c.AddTunAddressesToClient(clientTunIPs)

	c.SetClientState(clients.Authenticated)

	if err := c.ECDH(); err != nil {
		logger.Error("ECDH", "error", err)
		clients.RemoveClient(addr)
		return
	}

	// Wait for OK from client after ECDH
	buf, err = c.ReadBuf()
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

	c.SetClientState(clients.Ready)
	network.ProcessTun("server", c)
}
