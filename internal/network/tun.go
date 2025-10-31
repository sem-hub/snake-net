package network

import (
	"log"
	"sync"

	"github.com/sem-hub/snake-net/internal/clients"
	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/tun"
)

const MTU = 1420
var tunDev tun.Device

func SetUpTUN(c *configs.Config) error {
	var err error
	tunDev, err = tun.CreateTUN("snake", MTU)
	if err != nil {
		log.Fatal(err)
	}

	tunName, err := tunDev.Name()
	if err != nil {
		panic("Get tun name")
	}
	log.Printf("Interface Name: %s\n", tunName)

	link, err := netlink.LinkByName(tunName)
	if err != nil {
		return err
	}
	addr, err := netlink.ParseAddr(c.TunAddr)
	if err != nil {
		return err
	}
	configs.GetLogger().Info("SetUpTUN", "addr", addr)
	err = netlink.AddrAdd(link, addr)
	if err != nil {
		return err
	}
	addr6, err := netlink.ParseAddr(c.TunAddr6)
	if err != nil {
		return err
	}
	configs.GetLogger().Info("SetUpTUN", "addr6", addr6)
	err = netlink.AddrAdd(link, addr6)
	if err != nil {
		return err
	}

	err = netlink.LinkSetMTU(link, MTU)
	if err != nil {
		return err
	}
	err = netlink.LinkSetUp(link)
	if err != nil {
		return err
	}

	return nil
}

func ProcessTun(mode string, c *clients.Client) {
	logger := configs.GetLogger()
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
					logger.Error("Error reading from net buffer", "error", err)
					// Ignore bad packet
					continue
				}
				logger.Debug("TUN: Read from net", "len", len(buf))

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
			logger.Debug("TUN: Write to net", "len", len(data))
			if mode == "server" {
				clients.Route(data)
			} else {
				// Do not send data if client not authenticated
				c := clients.FindClient(c.GetClientAddr())
				if c.GetClientState() != clients.Ready {
					logger.Debug("Client not ready, drop packet", "addr", c.GetClientAddr())
					continue
				}
				if err := c.Write(&data, clients.NoneCmd); err != nil {
					logger.Error("Write to net", "error", err)
					break
				}
			}
		}
		err := c.Close()
		if err != nil {
			logger.Error("Close client", "error", err)
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

			bufs[0] = make([]byte, MTU)
			sizes[0] = MTU
			if count, err = tunDev.Read(bufs, sizes, 0); err != nil {
				panic(err)
			}
			buf := bufs[0][:sizes[0]]
			logger.Debug("TUN: Read from tun", "count", count, "sizes", sizes[0])
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
			logger.Debug("TUN: Write into tun", "len", len(buf))
			if _, err := tunDev.Write(bufs, 16); err != nil {
				panic(err)
			}
		}
	}()
	wg.Wait()
}
