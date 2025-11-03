package network

import (
	"errors"
	"log"
	"log/slog"
	"net"
	"net/netip"
	"os"

	"github.com/sem-hub/snake-net/internal/clients"
	"github.com/sem-hub/snake-net/internal/interfaces"
	"github.com/sem-hub/snake-net/internal/utils"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/tun"
)

const defaultMTU = 1420

type TunInterface struct {
	interfaces.TunInterface

	tunDev    tun.Device
	cidrs     []utils.Cidr
	mtu       int
	logger    *slog.Logger
	readBuffs [][]byte
}

var tunIf *TunInterface

func NewTUN(name string, cidrs []string, mtu int) (interfaces.TunInterface, error) {
	logger := slog.New(
		slog.NewTextHandler(
			os.Stderr,
			&slog.HandlerOptions{
				Level: slog.LevelDebug,
			},
		),
	)
	slog.SetDefault(logger)

	iface := TunInterface{}
	iface.logger = logger
	var err error
	if mtu == 0 {
		mtu = defaultMTU
	}
	iface.mtu = mtu

	for _, cidrStr := range cidrs {
		ip, net, err := net.ParseCIDR(cidrStr)
		if err != nil {
			return nil, err
		}
		netipAddr, _ := netip.AddrFromSlice(ip)
		netipAddr = netipAddr.Unmap()
		logger.Info("Add CIDR to TUN", "cidr", cidrStr, "ip", netipAddr.String())
		iface.cidrs = append(iface.cidrs, utils.Cidr{IP: netipAddr, Network: net})
	}

	iface.tunDev, err = tun.CreateTUN(name, mtu)
	if err != nil {
		log.Fatal(err)
	}

	tunName, err := iface.tunDev.Name()
	if err != nil {
		panic("Get tun name")
	}
	log.Printf("Interface Name: %s\n", tunName)

	link, err := netlink.LinkByName(tunName)
	if err != nil {
		return nil, err
	}

	for _, cidr := range iface.cidrs {
		nladdr, err := netlink.ParseAddr(cidr.String())
		if err != nil {
			return nil, err
		}
		mask, _ := cidr.Network.Mask.Size()
		logger.Info("Set address for TUN", "addr", cidr.IP.String(), "mask", mask)
		err = netlink.AddrAdd(link, nladdr)
		if err != nil {
			return nil, err
		}
	}
	/*err = netlink.LinkSetMTU(link, mtu)
	if err != nil {
		return nil, err
	}*/
	err = netlink.LinkSetUp(link)
	if err != nil {
		return nil, err
	}

	tunIf = &iface
	return &iface, nil
}

func (tunIf *TunInterface) WriteTun(buf []byte) error {
	if tunIf == nil {
		slog.Debug("WriteTun: did not initialized yet")
		return errors.New("did not initialized")
	}
	bufs := make([][]byte, 1)
	// 16 for additional header will work always
	bufs[0] = make([]byte, len(buf)+16)
	copy(bufs[0][16:], buf)
	tunIf.logger.Debug("TUN: Write into tun", "len", len(buf))
	if _, err := tunIf.tunDev.Write(bufs, 16); err != nil {
		return err
	}
	return nil
}

// Read from TUN and pass to client
func ProcessTun(mode string, c *clients.Client) {
	if tunIf == nil {
		log.Fatal("TUN interface not initialized")
	}
	for {
		buf := ReadTun()
		tunIf.logger.Debug("TUN: Read from tun", "len", len(buf))
		// send to all clients except the sender
		if mode == "server" {
			found := clients.Route(buf)
			// if no client found, write into local tun interface channel.
			if !found {
				c.ProcessMessageFromTun(mode, buf)
			}
		} else {
			// write into local tun interface channel.
			c.ProcessMessageFromTun(mode, buf)
		}
	}
}

func ReadTun() []byte {
	if len(tunIf.readBuffs) > 0 {
		buf := tunIf.readBuffs[0]
		tunIf.readBuffs = tunIf.readBuffs[1:]
		tunIf.logger.Debug("TUN: Read from tun (from buffer)", "len", len(buf))
		return buf
	}

	// Allocate batch buffers
	batchSize := 32
	bufs := make([][]byte, batchSize)
	sizes := make([]int, batchSize)
	for i := 0; i < batchSize; i++ {
		bufs[i] = make([]byte, tunIf.mtu+100)
		sizes[i] = tunIf.mtu
	}

	var count int
	var err error

	if count, err = tunIf.tunDev.Read(bufs, sizes, 0); err != nil {
		panic(err)
	}
	if count != 1 {
		tunIf.logger.Debug("TUN: Read multiple buffers", "count", count)
		tunIf.readBuffs = append(tunIf.readBuffs, bufs[1:count]...)
	}
	buf := bufs[0][:sizes[0]]
	tunIf.logger.Debug("TUN: Read from tun", "count", count, "sizes", sizes[0])
	return buf
}
