package utils

import (
	"net"
	"net/netip"
	"strconv"
)

type Cidr struct {
	IP      netip.Addr
	Network *net.IPNet
}

func (c Cidr) Contains(addr netip.Addr) bool {
	return c.Network.Contains(addr.AsSlice())
}

func (c Cidr) String() string {
	str := c.IP.String() + "/"
	prefixSize, _ := c.Network.Mask.Size()
	str += strconv.Itoa(prefixSize)
	return str
}

func MakeAddrPort(ip netip.Addr, port uint16) netip.AddrPort {
	return netip.AddrPortFrom(ip, port)
}

func NextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}
	return next
}
