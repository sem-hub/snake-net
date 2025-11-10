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
	if c != nil && c.GetClientState() == Ready {
		go func(cl *Client) {
			err := cl.Write(&data, NoneCmd)
			if err != nil {
				c.logger.Error("Route write", "error", err)
			}
		}(c)
	}
}

func Route(data []byte) bool {
	logger := configs.InitLogger("route")
	clientsLock.Lock()
	clientsCopy := make([]Client, len(clients))
	for i, c := range clients {
		clientsCopy[i] = *c
	}
	clientsLock.Unlock()

	address, ok := getDstIP(data)
	if !ok {
		logger.Error("Route: no destination IP found. Ignore.")
		return false
	}
	logger.Debug("Route", "address", address, "data len", len(data), "clientsCopy", len(clientsCopy), "clients", len(clients))
	// XXX read route table
	found := false
	for _, c := range clientsCopy {
		logger.Debug("Route loop", "address", c.address, "tunAddrs", c.tunAddrs)
		for _, tunAddr := range c.tunAddrs {
			logger.Debug("Route", "address", address, "cidrIP", tunAddr.IP, "cidrNetwork", tunAddr.Network, "clientState", c.GetClientState())
			if tunAddr.IP == address {
				sendDataToClient(c.address, data)
				found = true
				break
			}
		}
	}
	logger.Debug("Route", "found", found)
	// Check if address is in server's own CIDRs
	if !found {
		logger.Debug("Route: no matching client found. Send to all clients", "len(clients)", len(clientsCopy))
		for _, c := range clientsCopy {
			sendDataToClient(c.address, data)
		}
	}
	return found
}

// Read from NET, write to TUN
func (c *Client) RunReadLoop(mode string) {
	go func() {
		for {
			if c != nil && !c.IsClosed() {
				buf, err := c.ReadBuf(HEADER)
				if err != nil {
					c.logger.Error("Error reading from net buffer", "error", err)
					// Check if the client closed
					if c.IsClosed() {
						tunIf.SetExit()
						break
					}
					// Ignore bad packet
					continue
				}
				c.logger.Debug("TUN: Read from net", "len", len(buf), "mode", mode)

				// send to all clients except the sender
				if mode == "server" {
					if Route(buf) {
						continue
					}
					// if no client found, write into local tun interface channel.
				}
				// write into local tun interface channel.
				if tunIf != nil {
					tunIf.WriteTun(buf)
				} else {
					c.logger.Debug("RunReadLoop: ignore packet. Did not initialized yet")
				}
			} else {
				break
			}
		}
	}()
}
