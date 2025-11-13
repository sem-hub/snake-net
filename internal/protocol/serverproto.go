package protocol

import (
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

func checkIP(cidrStr string) error {
	logger.Debug("CIDR", "clientNet", cidrStr)
	ip, _, err := net.ParseCIDR(cidrStr)
	if err != nil {
		logger.Error("Failed to parse CIDR from client", "error", err)
		return err
	}
	logger.Debug("IP from client", "ip", ip)

	for _, cidr := range configs.GetConfig().TunAddrs {
		logger.Debug("Check client IP in server CIDR", "cidr", cidr)
		if cidr.Network.Contains(ip) {
			// Check already connected client's IP
			ipAddr, _ := netip.AddrFromSlice(ip)
			addrPort := utils.MakeAddrPort(ipAddr.Unmap(), 0)
			if clients.FindClient(addrPort) != nil {
				logger.Error("Client IP already in use", "ip", ip.String())
				return errors.New("Client IP " + ip.String() + " already in use")
			}
			return nil
		}
	}

	return errors.New("Client IP " + ip.String() + " not in any server Network")

}

func IdentifyClient(c *clients.Client) ([]utils.Cidr, error) {
	cidrs := make([]utils.Cidr, 0)

	buf, err := c.ReadBuf(clients.HEADER)
	if err != nil {
		return nil, err
	}
	if len(buf) < clients.HEADER {
		return nil, errors.New("invalid buffer length")
	}

	eol := strings.Index(string(buf), "\x00")
	str := strings.Fields(string(buf[:eol]))
	logger.Debug("IdentifyClient", "ID string", string(buf[:eol]))

	if len(str) == 0 {
		return nil, errors.New("invalid identification string")
	}
	h := str[0]
	clientId := str[1]
	clientCidr := str[2:]
	logger.Debug("IdentifyClient", "h", h, "clientId", clientId, "clientCidrs", clientCidr)
	if h == "Hello" {
		for _, clientNet := range clientCidr {
			// Check every IP client sent to us
			err := checkIP(clientNet)
			if err != nil {
				logger.Error("IdentifyClient: invalid client CIDR", "cidr", clientNet, "error", err)
				buf = []byte("Error: " + err.Error() + "\x00")
				buf = append(buf, clients.MakePadding()...)
				err = c.Write(&buf, clients.NoneCmd)
				if err != nil {
					logger.Error("Failed to write Error message", "error", err)
					return nil, err
				}
			}

			// IP is good, add it to list
			ip, network, _ := net.ParseCIDR(clientNet)
			netIp, _ := netip.AddrFromSlice(ip)
			cidrs = append(cidrs, utils.Cidr{IP: netIp.Unmap(), Network: network})
			logger.Debug("Added CIDR from client", "cidrs", cidrs)
		}
		c.SetClientId(clientId)
	} else {
		logger.Error("IdentifyClient: invalid first word", "word", h)
		buf := []byte("Error: Identification error\x00")
		buf = append(buf, clients.MakePadding()...)
		if err := c.Write(&buf, clients.NoneCmd); err != nil {
			logger.Error("Failed to write Error message", "error", err)
			return nil, err
		}

		return nil, errors.New("Identification error on first word")
	}

	logger.Info("IdentifyClient OK", "addr", c.GetClientAddr().String())
	msg := []byte("Welcome")
	for _, cidr := range configs.GetConfig().TunAddrs {
		msg = append(msg, ' ')
		msg = append(msg, []byte(cidr.IP.Unmap().String())...)
	}
	msg = append(msg, '\x00')
	logger.Debug("Welcome message", "msg", msg)
	msg = append(msg, clients.MakePadding()...)
	if err := c.Write(&msg, clients.NoneCmd); err != nil {
		logger.Error("Failed to write Welcome message", "error", err)
		return nil, err
	}

	buf, err = c.ReadBuf(clients.HEADER)
	if err != nil {
		return nil, err
	}
	if len(buf) < 2 {
		return nil, errors.New("invalid buffer length")
	}
	logger.Debug("IdentifyClient", "Final string", string(buf))
	if string(buf[:2]) != "OK" {
		return nil, errors.New("Identification not OK")
	}
	logger.Debug("CIDR from client", "cidrs", cidrs)
	return cidrs, nil
}

func ProcessNewClient(t transport.Transport, addr netip.AddrPort) {
	logger.Info("ProcessNewClient", "gotAddr", addr.String())

	c := clients.NewClient(addr, t)
	s := crypt.NewSecrets()
	c.AddSecretsToClient(s)
	c.ReadLoop(addr)

	clientTunIPs, err := IdentifyClient(c)
	if err != nil {
		logger.Error("Identification failed", "error", err)
		buf := []byte("Error: " + err.Error() + "\x00")
		buf = append(buf, clients.MakePadding()...)
		if err := c.Write(&buf, clients.NoneCmd); err != nil {
			logger.Error("Failed to write Error message", "error", err)
		}
		clients.RemoveClient(addr)
		return
	}
	logger.Info("Identification passed", "clientTunIPs", clientTunIPs)
	c.AddTunAddressesToClient(clientTunIPs)

	c.SetClientState(clients.Authenticated)

	if err := c.ECDH(); err != nil {
		logger.Error("ECDH", "error", err)
		clients.RemoveClient(addr)
		return
	}

	// Wait for OK from client after ECDH
	buf, err := c.ReadBuf(clients.HEADER)
	if err != nil {
		logger.Error("Failed to read response message", "error", err)
		clients.RemoveClient(addr)
		return
	}

	if len(buf) < 2 || string(buf[:2]) != "OK" {
		logger.Error("Invalid server response", "len", len(buf), "msg", string(buf))
		clients.RemoveClient(addr)
		return
	}

	c.SetClientState(clients.Ready)
	c.NetLoop("server")
	c.CreatePinger()
	network.ProcessTun()
}
