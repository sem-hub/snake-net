package network

import (
	"log"
	"sync"

	"github.com/sem-hub/snake-net/internal/clients"
	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

var tun *water.Interface

func SetUpTUN(c *configs.Config) error {
	var err error
	tun, err = water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Interface Name: %s\n", tun.Name())

	link, err := netlink.LinkByName(tun.Name())
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
	err = netlink.LinkSetMTU(link, 1436)
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
	rCh := make(chan []byte)
	wCh := make(chan []byte)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			buf, err := c.ReadBuf()
			if err != nil {
				logger.Error("Error reading from buffer", "error", err)
				// Ignore bad packet
				continue
			}
			logger.Debug("Read from net", "len", len(buf))

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
	}()
	// read from local tun interface channel, and write into remote net channel.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			data := <-rCh
			logger.Debug("Write to net", "len", len(data))
			if mode == "server" {
				clients.Route(data)
			} else {
				// Do not send data if client not authenticated
				c := clients.FindClient(c.GetClientAddr())
				if c.GetClientState() != clients.Ready {
					logger.Debug("Client not authenticated, drop packet", "addr", c.GetClientAddr())
					continue
				}
				c.Write(&data)
				/*if err := c.Write(&data); err != nil {
					logger.Error("Write to net", "error", err)
					break
				}*/
			}
		}
		/*err := s.Close()
		if err != nil {
			logger.Error("Close crypt", "error", err)
		}*/
	}()

	// read data from tun into rCh channel.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			buf := make([]byte, 1522)
			var n int
			var err error

			if n, err = tun.Read(buf); err != nil {
				panic(err)
			}
			buf = buf[:n]
			logger.Debug("Read from tun", "len", n)
			rCh <- buf
		}
	}()
	// write data into tun from wCh channel.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			buf := <-wCh
			logger.Debug("Write into tun", "len", len(buf))
			if _, err := tun.Write(buf); err != nil {
				panic(err)
			}
		}
	}()
	wg.Wait()
}
