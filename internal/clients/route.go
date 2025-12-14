package clients

import (
	"net/netip"

	"github.com/sem-hub/snake-net/internal/configs"

	//lint:ignore ST1001 reason: it's safer to use . import here to avoid name conflicts
	. "github.com/sem-hub/snake-net/internal/interfaces"
)

func getDstIP(packet []byte) (netip.Addr, bool) {
	if len(packet) < 1 {
		return netip.Addr{}, false
	}
	version := packet[0] >> 4 // First 4 bits
	if version == 4 {
		// IPv4: destination address is at bytes 16-19 (inclusive)
		return netip.AddrFromSlice(packet[16:20])
	}
	if version == 6 {
		// IPv6: destination address is at bytes 24-39 (inclusive)
		return netip.AddrFromSlice(packet[24:40])
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

func Route(sourceClient netip.AddrPort, data []byte) bool {
	logger := configs.InitLogger("route")

	address, ok := getDstIP(data)
	if !ok {
		logger.Error("Route: no destination IP found. Ignore.")
		return false
	}
	logger.Debug("Route", "address", address, "data_len", len(data), "clients_num", len(clients))
	clientsLock.RLock()
	cl, found := tunAddrs[address]
	clientsLock.RUnlock()

	logger.Debug("Route", "found", found)
	if found {
		sendDataToClient(cl.address, data)
	} else {
		for _, cidr := range configs.GetConfig().TunAddrs {
			logger.Debug("Route: checking cidr", "cidr", cidr.String())
			if cidr.IP == address {
				// It's packet for us. Send it into tun
				logger.Debug("Route: packet for us. Write into TUN", "address", address)
				return false
			}
		}

		logger.Debug("Route: no matching client found. Send to all clients")
		addrs := make([]netip.AddrPort, 0)
		clientsLock.RLock()
		for _, c := range clients {
			addrs = append(addrs, c.address)
		}
		clientsLock.RUnlock()

		// Send to all except client we got the packet
		for _, addr := range addrs {
			if addr != sourceClient {
				sendDataToClient(addr, data)
			}
		}
	}
	return found
}

// Read from NET, write to TUN
func (c *Client) ProcessNetworkDataLoop(mode string) {
	go func() {
		for {
			if c != nil && !c.IsClosed() {
				buf, err := c.ReadBuf(HEADER)
				if err != nil {
					c.logger.Error("Error reading from net buffer", "error", err)
					// Check if the client closed
					if c.IsClosed() {
						break
					}
					// Ignore bad packet
					continue
				}
				c.logger.Debug("NetLoop: Read from net", "len", len(buf), "mode", mode)

				// send to all clients except the sender
				if mode == "server" {
					if Route(c.address, buf) {
						continue
					}
					// if no client found, write into local tun interface channel.
				}
				// write into local tun interface channel.
				if tunIf != nil {
					tunIf.WriteTun(buf)
				} else {
					c.logger.Debug("NetLoop: ignore packet. Did not initialized yet")
				}
			} else {
				break
			}
		}
	}()
}
