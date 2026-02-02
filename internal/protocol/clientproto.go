package protocol

import (
	"context"
	"errors"
	"log"
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

// Client sends string: "Hello <client-id> <tun-addr1> <tun-addr2>"
// If everything is OK server responds with: "Welcome <server-ip1> <server-ip2> [<client-ip1> <client-ip2>] <cipher-name> [<signature-name>]"
// Otherwise server responds with error message.
// If client wants to get IP addresses from server it does not add TUN addresses to the message.
func Identification(c *clients.Client) ([]utils.Cidr, []utils.Cidr, string, string, error) {
	cfg := configs.GetConfig()
	serverIPs := make([]utils.Cidr, 0)
	clientIPs := make([]utils.Cidr, 0)
	chipherName := ""
	signatureName := ""

	msg := []byte("Hello " + cfg.ClientId)

	for _, addr := range cfg.TunAddrs {
		logger.Debug("Adding TUN address to identification", "addr", addr)
		msg = append(msg, ' ')
		prefLen, _ := addr.Network.Mask.Size()
		msg = append(msg, []byte(addr.IP.Unmap().String()+"/"+strconv.Itoa(prefLen))...)
	}
	if cfg.Engine != "" {
		msg = append(msg, ' ')
		msg = append(msg, []byte(cfg.Engine)...)
	}
	if cfg.SignEngine != "" {
		msg = append(msg, ' ')
		msg = append(msg, []byte(cfg.SignEngine)...)
	}
	logger.Debug("Identification", "msg", string(msg))
	err := c.Write(&msg, WithPadding)
	if err != nil {
		return nil, nil, "", "", err
	}

	msg1, err := c.ReadBuf(HEADER)
	if err != nil {
		return nil, nil, "", "", err
	}
	str := strings.Fields(string(msg1))
	logger.Debug("ID", "msg", string(msg1))

	if len(str) == 0 {
		return nil, nil, "", "", errors.New("invalid welcome string")
	}
	if str[0] == "Welcome" {
		i := 1
		for _, addr := range str[i : i+2] {
			logger.Debug("Server IPs", "addr", addr)
			ip, network, err := net.ParseCIDR(addr)
			netIp, _ := netip.AddrFromSlice(ip)
			if err != nil {
				// XXX send not OK to server
				logger.Error("invalid IP from welcome string", "addr", addr)
				return nil, nil, "", "", errors.New("invalid IP from welcome string: " + addr)
			}
			serverIPs = append(serverIPs, utils.Cidr{IP: netIp.Unmap(), Network: network})
			i++
		}
		for _, addr := range str[i : i+2] {
			logger.Debug("Client IPs", "addr", addr)
			ip, network, err := net.ParseCIDR(addr)
			netIp, _ := netip.AddrFromSlice(ip)
			if err != nil {
				// XXX send not OK to server
				logger.Error("invalid IP from welcome string", "addr", addr)
				return nil, nil, "", "", errors.New("invalid IP from welcome string: " + addr)
			}
			clientIPs = append(clientIPs, utils.Cidr{IP: netIp.Unmap(), Network: network})
			i++
		}
		if len(str) > i {
			chipherName = str[i]
		}
		if len(str) > i+1 {
			signatureName = str[i+1]
		}
	} else {
		return nil, nil, "", "", errors.New("Identification " + string(msg1))
	}
	buf := []byte{'O', 'K'}
	if err := c.Write(&buf, WithPadding); err != nil {
		logger.Error("Failed to write OK message", "error", err)
		return nil, nil, "", "", err
	}
	return serverIPs, clientIPs, chipherName, signatureName, nil
}

func ProcessServer(ctx context.Context, t transport.Transport, addr netip.AddrPort) error {
	cfg := configs.GetConfig()

	// Well, really it's server but we call it client here
	c := clients.NewClient(addr, t)
	defaultEngine := ""
	defaultSignature := ""
	if !t.IsEncrypted() {
		defaultEngine = "aes-cbc"
		defaultSignature = "ed25519"
	}
	// Bootstrap secrets
	s, err := crypt.NewSecrets(defaultEngine, cfg.Secret, defaultSignature)
	if err != nil {
		log.Fatal("Failed to create secrets engine: unknown engine")
	}
	c.AddSecretsToClient(s)

	c.TransportReadLoop(addr)
	c.CreatePinger()

	serverIPs, clientIPs, chipherName, signatureName, err := Identification(c)
	if err != nil {
		logger.Error("Identification Fails", "error", err)
		clients.RemoveClient(addr)
		return errors.New("Identification failed: " + err.Error())
	}
	logger.Info("Server accepted connection", "cipher", chipherName, "signature", signatureName)

	c.AddTunAddressesToClient(serverIPs)
	cfg.TunAddrs = clientIPs
	cfg.Engine = chipherName
	cfg.SignEngine = signatureName
	// Recreate secrets with new cipher if needed
	if s.Engine != nil && s.Engine.GetName() != chipherName {
		sNew, err := crypt.NewSecrets(chipherName, cfg.Secret, signatureName)
		if err != nil {
			logger.Error("Failed to create secrets engine", "err", err)
			clients.RemoveClient(addr)
			return errors.New("Failed to create secrets engine: " + err.Error())
		}
		logger.Info("Secrets engine changed", "old", s.Engine.GetName(), "new", sNew.Engine.GetName())
		c.AddSecretsToClient(sNew)
	}

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

	if cfg.Socks5Enabled {
		go func() {
			network.RunSOCKS5(ctx, int(cfg.Socks5Port), cfg.Socks5Username, cfg.Socks5Password)
		}()
	}

	c.SetClientState(clients.Ready)

	c.ProcessNetworkDataLoop("client")
	logger.Info("client started", "address", addr.String())
	network.ProcessTun()
	logger.Debug("client finished")
	return nil
}
