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
)

func IdentifyClient(c *clients.Client) (net.Addr, net.Addr, error) {
	var addr net.Addr
	var addr6 net.Addr

	buf, err := c.ReadBuf()
	if err != nil {
		return nil, nil, err
	}
	if len(buf) < 6 {
		return nil, nil, errors.New("invalid buffer length")
	}
	c.XOR(&buf)
	configs.GetLogger().Debug("IdentifyClient", "ID string", string(buf))
	sep := strings.Index(string(buf), "\x00")
	str := strings.Fields(string(buf[:sep]))
	if len(str) != 3 {
		return nil, nil, errors.New("invalid identification string")
	}
	h := str[0]
	clientNet := str[1]
	clientNet6 := str[2]
	configs.GetLogger().Debug("IdentifyClient", "h", h, "clientNet", clientNet, "clientNet6", clientNet6)
	if h == "Hello" {
		ip, _, err := net.ParseCIDR(clientNet)
		if err != nil {
			return nil, nil, err
		}
		ip6, _, err := net.ParseCIDR(clientNet6)
		if err != nil {
			return nil, nil, err
		}

		_, myNetwork, err := net.ParseCIDR(configs.GetConfig().TunAddr)
		if err != nil {
			return nil, nil, err
		}
		if !myNetwork.Contains(ip) {
			buf = []byte("Error: IP not in " + myNetwork.String())
			c.Write(&buf, clients.NoneCmd)

			return nil, nil, errors.New("Client IP " + ip.String() + " not in " +
				myNetwork.String())
		}
		_, myNetwork6, err := net.ParseCIDR(configs.GetConfig().TunAddr6)
		if err != nil {
			return nil, nil, err
		}
		if !myNetwork6.Contains(ip6) {
			buf = []byte("Error: IP not in " + myNetwork6.String())
			c.Write(&buf, clients.NoneCmd)

			return nil, nil, errors.New("Client IP " + ip6.String() + " not in " +
				myNetwork6.String())
		}

		addr = &net.IPAddr{IP: ip}
		addr6 = &net.IPAddr{IP: ip6}
		configs.GetLogger().Debug("IdentifyClient OK", "addr", addr, "addr6", addr6)
		if err := c.WriteWithXORAndPadding([]byte("Welcome"), true); err != nil {
			configs.GetLogger().Debug("Failed to write Welcome message", "error", err)
			return nil, nil, err
		}
	} else {
		if err := c.WriteWithXORAndPadding([]byte("Error"), true); err != nil {
			configs.GetLogger().Debug("Failed to write Error message", "error", err)
			return nil, nil, err
		}

		return nil, nil, errors.New("Identification error")
	}
	buf, err = c.ReadBuf()
	if err != nil {
		return nil, nil, err
	}
	if len(buf) < 2 {
		return nil, nil, errors.New("invalid buffer length")
	}
	c.XOR(&buf)
	configs.GetLogger().Debug("IdentifyClient", "Final string", string(buf))
	if string(buf[:2]) != "OK" {
		return nil, nil, errors.New("Identification not OK")
	}
	return addr, addr6, nil
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

	clientTunIP, clientTunIP6, err := IdentifyClient(c)
	if err != nil {
		logger.Debug("Identification failed", "error", err)
		clients.RemoveClient(addr)
		return
	}
	logger.Debug("Identification passed", "clientTunIP", clientTunIP)
	c.AddTunAddressToClient(clientTunIP, clientTunIP6)

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
	//fmt.Println("Session public key: ", c.GetPublicKey())
	network.ProcessTun("server", c)
}
