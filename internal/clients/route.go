package clients

import (
	"net"
	"net/netip"

	"github.com/sem-hub/snake-net/internal/configs"
)

func getDstIP(packet []byte) (netip.Addr, bool) {
	if len(packet) < 1 {
		return netip.Addr{}, false
	}
	version := packet[0] >> 4 // First 4 bits
	if version == 4 {
		return netip.AddrFromSlice(packet[16:20]) // IPv4 address in bytes 16-19
	}
	if version == 6 {
		return netip.AddrFromSlice(packet[24:40]) // IPv6 address in bytes 24-39
	}
	return netip.Addr{}, false
}

// Find real client and send data to it in background
func sendDataToClient(addr netip.AddrPort, data []byte) {
	c := FindClient(addr)
	go func(cl *Client) {
		err := cl.Write(&data, NoneCmd)
		if err != nil {
			logger.Error("Route write", "error", err)
		}
	}(c)
}

func Route(data []byte) bool {
	clientsLock.Lock()
	clientsCopy := make([]Client, len(clients))
	for i, c := range clients {
		clientsCopy[i] = *c
	}
	clientsLock.Unlock()

	address, ok := getDstIP(data)
	if !ok {
		logger.Debug("Route: no destination IP found. Ignore.")
		return false
	}
	logger.Debug("Route", "address", address, "data len", len(data), "clientsCopy", len(clientsCopy), "clients", len(clients))
	// XXX read route table
	found := false
	for _, c := range clientsCopy {
		logger.Debug("Route", "address", address, "tun", c.tunAddr, "tun6", c.tunAddr6, "clientState", c.GetClientState())
		if c.tunAddr != nil && c.tunAddr.String() == address.String() {
			if c.GetClientState() == Ready {
				sendDataToClient(c.address, data)
			}
			found = true
			break
		}
		if c.tunAddr6 != nil && c.tunAddr6.String() == address.String() {
			if c.GetClientState() == Ready {
				sendDataToClient(c.address, data)
			}
			found = true
			break
		}
	}
	myIP, _, err := net.ParseCIDR(configs.GetConfig().TunAddr)
	if err != nil {
		logger.Error("Route", "error", err)
		return true
	}
	myIP6, _, err := net.ParseCIDR(configs.GetConfig().TunAddr6)
	if err != nil {
		logger.Error("Route", "error", err)
		return true
	}
	if !found && !myIP.Equal(address.AsSlice()) && myIP6.Equal(address.AsSlice()) {
		logger.Debug("Route: no matching client found. Send to all clients")
		for _, c := range clientsCopy {
			if c.GetClientState() == Ready {
				sendDataToClient(c.address, data)
			}
		}
	}
	return found
}
