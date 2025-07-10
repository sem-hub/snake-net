package network

import (
	"log"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

func SetUpTUN(c *configs.Config) error {
	ifce, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Interface Name: %s\n", ifce.Name())

	link, err := netlink.LinkByName(ifce.Name())
	if err != nil {
		return err
	}
	addr, err := netlink.ParseAddr(c.TunAddr)
	if err != nil {
		return err
	}
	err = netlink.AddrAdd(link, addr)
	if err != nil {
		return err
	}
	err = netlink.LinkSetUp(link)
	if err != nil {
		return err
	}

	return nil
}
