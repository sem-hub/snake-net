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

	//lint:ignore ST1001 reason: it's safer to use . import here to avoid name conflicts
	. "github.com/sem-hub/snake-net/internal/interfaces"
	"github.com/sem-hub/snake-net/internal/network"
	"github.com/sem-hub/snake-net/internal/network/transport"
	"github.com/sem-hub/snake-net/internal/utils"
)

func Identification(c *clients.Client) ([]utils.Cidr, error) {
	cidrs := make([]utils.Cidr, 0)

	cfg := configs.GetConfig()

	msg := []byte("Hello " + cfg.ClientId)

	for _, addr := range cfg.TunAddrs {
		logger.Debug("Adding TUN address to identification", "addr", addr)
		msg = append(msg, ' ')
		prefLen, _ := addr.Network.Mask.Size()
		msg = append(msg, []byte(addr.IP.Unmap().String()+"/"+strconv.Itoa(prefLen))...)
	}
	logger.Debug("Identification", "msg", string(msg))
	err := c.Write(&msg, WithPadding)
	if err != nil {
		return nil, err
	}

	msg1, err := c.ReadBuf(HEADER)
	if err != nil {
		return nil, err
	}
	str := strings.Fields(string(msg1))
	logger.Debug("ID", "msg", string(msg1))

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
		return nil, errors.New("Identification " + string(msg1))
	}
	buf := []byte{'O', 'K'}
	if err := c.Write(&buf, WithPadding); err != nil {
		logger.Error("Failed to write OK message", "error", err)
		return nil, err
	}
	return cidrs, nil
}

func ProcessServer(t transport.Transport, addr netip.AddrPort) error {
	cfg := configs.GetConfig()

	// Well, really it's server but we call it client here
	c := clients.NewClient(addr, t)
	s := crypt.NewSecrets(configs.GetConfigFile().Crypt.Engine, cfg.Secret)
	if s == nil {
		logger.Error("Failed to create secrets engine", "error", "unknown engine")
		return errors.New("failed to create secrets engine: unknown engine")
	}
	c.AddSecretsToClient(s)

	c.TransportReadLoop(addr)
	c.CreatePinger()

	serverIPs, err := Identification(c)
	if err != nil {
		logger.Error("Identification Fails", "error", err)
		clients.RemoveClient(addr)
		return errors.New("Identification failed: " + err.Error())
	}
	logger.Info("Identification Success")

	c.AddTunAddressesToClient(serverIPs)

	c.SetClientState(clients.Authenticated)

	if err := c.ECDH(); err != nil {
		logger.Error("ECDH", "error", err)
		clients.RemoveClient(addr)
		return errors.New("ECDH failed: " + err.Error())
	}

	buf := []byte{'O', 'K'}
	if err := c.Write(&buf, WithPadding); err != nil {
		logger.Error("Failed to write OK message", "error", err)
		clients.RemoveClient(addr)
		return errors.New("Failed to write OK message: " + err.Error())
	}

	// Set up TUN interface
	logger.Info("TUN Addresses", "addrs", cfg.TunAddrs)

	tunIf, err := network.NewTUN(cfg.TunName, cfg.TunAddrs, cfg.TunMTU)
	if err != nil {
		logger.Error("Error creating tun interface", "error", err)
		return errors.New("Error creating tun interface: " + err.Error())
	}
	clients.SetTunInterface(tunIf)

	c.SetClientState(clients.Ready)

	c.ProcessNetworkDataLoop("client")
	logger.Info("client started", "address", addr.String())
	network.ProcessTun()
	logger.Debug("client finished")
	return nil
}
