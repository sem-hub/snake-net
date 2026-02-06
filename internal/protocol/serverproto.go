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

func DynamicClientIPs(tunAddrs []utils.Cidr) []utils.Cidr {
	clientIPs := make([]utils.Cidr, 0)
	for _, cidr := range tunAddrs {
		ipNet := cidr.Network
		for ip := utils.NextIP(cidr.IP.AsSlice()); ipNet.Contains(ip); ip = utils.NextIP(ip) {
			// Check already connected client's IP
			ipAddr, _ := netip.AddrFromSlice(ip)
			if clients.FindClientTunAddr(ipAddr.Unmap()) == nil {
				clientIPs = append(clientIPs, utils.Cidr{IP: ipAddr.Unmap(), Network: cidr.Network})
				logger.Debug("DynamicClientIPs: assigned IP to client", "ip", ip.String())
				break
			}
		}
	}
	return clientIPs
}

func IdentifyClient(c *clients.Client) ([]utils.Cidr, string, string, error) {
	clientIPs := make([]utils.Cidr, 0)
	cfg := configs.GetConfig()

	buf, err := c.ReadBuf(HEADER)
	if err != nil {
		return nil, "", "", err
	}
	if len(buf) < HEADER {
		return nil, "", "", errors.New("invalid buffer length")
	}

	str := strings.Fields(string(buf))
	logger.Debug("IdentifyClient", "ID string", string(buf))

	if len(str) == 0 {
		return nil, "", "", errors.New("invalid identification string")
	}
	h := str[0]
	clientId := str[1]
	clientCidr := make([]string, 0)
	i := 2
	if len(str) > 2 {
		for _, addr := range str[2 : len(str)-1] {
			err := checkIP(addr)
			if err != nil {
				logger.Debug("Not IP string: ", "err", err)
				break
			}
			clientCidr = append(clientCidr, addr)
			i++
		}
	}
	logger.Debug("IdentifyClient", "h", h, "clientId", clientId, "clientCidrs", clientCidr)
	if h == "Hello" {
		for _, clientNet := range clientCidr {
			// Check every IP client sent to us
			err := checkIP(clientNet)
			if err != nil {
				logger.Debug("Not IP string: ", "err", err)
				break
			}

			// IP is good, add it to list
			ip, network, _ := net.ParseCIDR(clientNet)
			netIp, _ := netip.AddrFromSlice(ip)
			clientIPs = append(clientIPs, utils.Cidr{IP: netIp.Unmap(), Network: network})
			logger.Debug("Added CIDR from client", "cidrs", clientIPs)
		}
		c.SetClientId(clientId)
	} else {
		logger.Error("IdentifyClient: invalid first word", "word", h)
		buf := []byte("Error: Identification error")
		if err := c.Write(&buf, WithPadding); err != nil {
			logger.Error("Failed to write Error message", "error", err)
			return nil, "", "", err
		}

		return nil, "", "", errors.New("Identification error on first word")
	}

	if len(clientIPs) == 0 {
		logger.Info("Client requested IPs from server")
		clientIPs = DynamicClientIPs(cfg.TunAddrs)
	}

	logger.Info("IdentifyClient OK", "addr", c.GetClientAddr().String())
	msg := []byte("Welcome")
	for _, cidr := range cfg.TunAddrs {
		msg = append(msg, ' ')
		prefLen, _ := cidr.Network.Mask.Size()
		msg = append(msg, []byte(cidr.IP.Unmap().String()+"/"+strconv.Itoa(prefLen))...)
	}
	for _, cidr := range clientIPs {
		msg = append(msg, ' ')
		prefLen, _ := cidr.Network.Mask.Size()
		msg = append(msg, []byte(cidr.IP.Unmap().String()+"/"+strconv.Itoa(prefLen))...)
	}

	// If transport is encrypted, don't neet to negotiate engines
	engineName := ""
	signatureName := ""
	if c.GetSecrets().Engine != nil {
		engineName = cfg.Engine
		signatureName = cfg.SignEngine
		if len(str) > i {
			// last two are engine and signature
			engineName = str[i]
			if len(str) > i+1 {
				signatureName = str[i+1]
			}
			logger.Info("Client requested engines", "engine", engineName, "signature", signatureName)
		}

		msg = append(msg, ' ')
		msg = append(msg, []byte(engineName)...)
		msg = append(msg, ' ')
		msg = append(msg, []byte(signatureName)...)
	}
	logger.Debug("Welcome message", "msg", string(msg))
	if err := c.Write(&msg, WithPadding); err != nil {
		logger.Error("Failed to write Welcome message", "error", err)
		return nil, "", "", err
	}

	err = clients.WaitForOKMessage(c)
	if err != nil {
		return nil, "", "", err
	}
	logger.Debug("IdentifyClient", "Final string", string(buf))
	logger.Debug("Final CIDR for client", "cidrs", clientIPs)
	return clientIPs, engineName, signatureName, nil
}

func ProcessNewClient(t transport.Transport, addr netip.AddrPort) {
	logger.Info("ProcessNewClient", "gotAddr", addr.String())
	cfg := configs.GetConfig()

	c := clients.NewClient(addr, t)

	// Bootstrap secrets
	defaultEngine := ""
	defaultSignature := "ed25519"
	if !t.IsEncrypted() {
		defaultEngine = "aes-cbc"
	}
	s, err := crypt.NewSecrets(defaultEngine, cfg.Secret, defaultSignature)
	if err != nil {
		logger.Fatal("Failed to create secrets engine", "error", err)
	}
	c.AddSecretsToClient(s)
	c.TransportReadLoop(addr)

	clientTunIPs, engineName, signatureName, err := IdentifyClient(c)
	if err != nil {
		logger.Error("Identification failed", "error", err)
		buf := []byte("Error: " + err.Error())
		if err := c.Write(&buf, WithPadding); err != nil {
			logger.Error("Failed to write Error message", "error", err)
		}
		clients.RemoveClient(addr)
		return
	}
	logger.Info("Identification passed", "clientTunIPs", clientTunIPs)
	logger.Info("Client accepted connection", "cipher", engineName, "signature", signatureName)

	// Recreate secrets with new cipher if needed
	if s.Engine != nil && s.Engine.GetName() != engineName {
		sNew, err := crypt.NewSecrets(engineName, cfg.Secret, signatureName)
		if err != nil {
			logger.Error("Failed to create secrets engine", "err", err)
			clients.RemoveClient(addr)
			return
		}
		logger.Info("Secrets engine changed", "old", s.Engine.GetName(), "new", sNew.Engine.GetName())
		c.AddSecretsToClient(sNew)
	}
	c.AddTunAddressesToClient(clientTunIPs)

	c.SetClientState(clients.Authenticated)

	if t.IsEncrypted() {
		// zero-knowledge proof of shared secret knowledge
		logger.Debug("Comparing secrets with the client")
		// Read secret from client
		buf, err := c.ReadBuf(HEADER)
		if err != nil {
			logger.Error("Failed to read response message", "error", err)
			clients.RemoveClient(addr)
			return
		}

		if !s.SignatureEngine.Verify(s.GetSharedSecret(), buf) {
			logger.Error("Client sent invalid secret")
			err = clients.SendErrorMessage(c, []byte("Error: Invalid secret"))
			if err != nil {
				logger.Error("Failed to write Error message", "error", err)
			}
			clients.RemoveClient(addr)
			return
		} else {
			logger.Debug("Client sent correct secret")
			err = clients.SendOKMessage(c)
			if err != nil {
				clients.RemoveClient(addr)
				return
			}
		}
	} else {
		logger.Debug("Performing ECDH key exchange with the client")
		if err := c.ECDH(); err != nil {
			logger.Error("ECDH", "error", err)
			clients.RemoveClient(addr)
			return
		}

		err = clients.WaitForOKMessage(c)
		if err != nil {
			logger.Error("Got not OK message", "error", err)
			clients.RemoveClient(addr)
			return
		}
	}

	c.SetClientState(clients.Ready)
	c.ProcessNetworkDataLoop("server")
	c.CreatePinger()
	network.ProcessTun()
}
