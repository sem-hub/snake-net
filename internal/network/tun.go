package network

import (
	"log"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"

	"github.com/sem-hub/snake-net/internal/clients"
	"github.com/sem-hub/snake-net/internal/utils"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/tun"
)

const defaultMTU = 1420

type TunInterface struct {
	tunDev tun.Device
	cidrs  []utils.Cidr
	mtu    int
	logger *slog.Logger
}

var tunIf *TunInterface

func NewTUN(name string, cidrs []string, mtu int) (*TunInterface, error) {
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

func ProcessTun(mode string, c *clients.Client) {
	if tunIf == nil {
		log.Fatal("TUN interface not initialized")
	}
	tunIf.Process(mode, c)
}

func (iface *TunInterface) Process(mode string, c *clients.Client) {
	wg := sync.WaitGroup{}
	// local tun interface read and write channel.
	rCh := make(chan []byte, 64)
	wCh := make(chan []byte, 64)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			if c != nil {
				buf, err := c.ReadBuf()
				if err != nil {
					iface.logger.Error("Error reading from net buffer", "error", err)
					// Ignore bad packet
					continue
				}
				iface.logger.Debug("TUN: Read from net", "len", len(buf), "mode", mode)

				// send to all clients except the sender
				if mode == "server" {
					found := clients.Route(buf)
					// if no client found, write into local tun interface channel.
					if !found {
						wCh <- buf
					}
				} else {
					// write into local tun interface channel.
					wCh <- buf
				}
			}
		}
	}()
	// read from local tun interface channel, and write into remote net channel.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			data := <-rCh
			iface.logger.Debug("TUN: Write to net", "len", len(data), "mode", mode)
			if mode == "server" {
				clients.Route(data)
			} else {
				// Do not send data if client not authenticated
				c := clients.FindClient(c.GetClientAddr())
				if c.GetClientState() != clients.Ready {
					iface.logger.Debug("Client not ready, drop packet", "addr", c.GetClientAddr())
					continue
				}
				if err := c.Write(&data, clients.NoneCmd); err != nil {
					iface.logger.Error("Write to net", "error", err)
					break
				}
			}
		}
		err := c.Close()
		if err != nil {
			iface.logger.Error("Close client", "error", err)
		}
	}()

	// read data from tun into rCh channel.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			batchSize := 1 // 128
			bufs := make([][]byte, batchSize)
			sizes := make([]int, batchSize)

			var count int
			var err error

			bufs[0] = make([]byte, iface.mtu)
			sizes[0] = iface.mtu
			if count, err = iface.tunDev.Read(bufs, sizes, 0); err != nil {
				panic(err)
			}
			buf := bufs[0][:sizes[0]]
			iface.logger.Debug("TUN: Read from tun", "count", count, "sizes", sizes[0])
			rCh <- buf
		}
	}()
	// write data into tun from wCh channel.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			//batchSize := 128
			bufs := make([][]byte, 1)
			buf := <-wCh
			// 16 for additional header will work always. But really for Windows it must be 0, for BSD must be 4, for Linux is 14.
			// XXX It'll be work but not beautiful
			bufs[0] = make([]byte, len(buf)+16)
			copy(bufs[0][16:], buf[:])
			iface.logger.Debug("TUN: Write into tun", "len", len(buf))
			if _, err := iface.tunDev.Write(bufs, 16); err != nil {
				panic(err)
			}
		}
	}()
	wg.Wait()
}
