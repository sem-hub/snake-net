//go:build linux

package network

import (
	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/vishvananda/netlink"
)

func (iface *TunInterface) setUpInterface() error {
	link, err := netlink.LinkByName(iface.name)
	if err != nil {
		return err
	}

	for _, cidr := range iface.cidrs {
		nladdr, err := netlink.ParseAddr(cidr.String())
		if err != nil {
			return err
		}
		mask, _ := cidr.Network.Mask.Size()
		configs.InitLogger("tun").Info("Set address for TUN", "addr", cidr.IP.String(), "mask", mask)
		err = netlink.AddrAdd(link, nladdr)
		if err != nil {
			return err
		}
	}
	err = netlink.LinkSetUp(link)
	if err != nil {
		return err
	}

	return nil
}
