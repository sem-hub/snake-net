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
