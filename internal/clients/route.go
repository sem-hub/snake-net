package clients

import (
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
	if c != nil {
		go func(cl *Client) {
			err := cl.Write(&data, NoneCmd)
			if err != nil {
				logger.Error("Route write", "error", err)
			}
		}(c)
	}
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
		for _, tunAddr := range c.tunAddrs {
			logger.Debug("Route", "address", address, "cidrIP", tunAddr.IP, "cidrNetwork", tunAddr.Network, "clientState", c.GetClientState())
			if tunAddr.IP == address {
				if c.GetClientState() == Ready {
					sendDataToClient(c.address, data)
				}
				found = true
				break
			}
		}
	}
	// Check if address is in server's own CIDRs
	if !found {
		myIPs := configs.GetConfig().TunAddrs
		for _, cidr := range myIPs {
			if cidr.IP != address {
				logger.Debug("Route: no matching client found. Send to all clients")
				for _, c := range clientsCopy {
					if c.GetClientState() == Ready {
						sendDataToClient(c.address, data)
					}
				}
			}
		}
	}
	return found
}
