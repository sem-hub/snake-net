package network

import (
	"log"
	"sync"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/crypt"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

func SetUpTUN(c *configs.Config) (*water.Interface, error) {
	ifce, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Interface Name: %s\n", ifce.Name())

	link, err := netlink.LinkByName(ifce.Name())
	if err != nil {
		return nil, err
	}
	addr, err := netlink.ParseAddr(c.TunAddr)
	if err != nil {
		return nil, err
	}
	err = netlink.AddrAdd(link, addr)
	if err != nil {
		return nil, err
	}
	err = netlink.LinkSetMTU(link, 1436)
	if err != nil {
		return nil, err
	}
	err = netlink.LinkSetUp(link)
	if err != nil {
		return nil, err
	}

	return ifce, nil
}

func ProcessTun(c *crypt.Secrets, tun *water.Interface) {
	logger := configs.GetLogger()
	wg := sync.WaitGroup{}
	// local tun interface read and write channel.
	rCh := make(chan []byte)
	wCh := make(chan []byte)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			buf, err := c.Read()
			if err != nil {
				logger.Error("Read packet from net", "error", err)
				// Ignore bad packet
				continue
			}
			logger.Debug("Read from net", "len", len(buf))
			// write into local tun interface channel.
			wCh <- buf
		}
	}()
	// read from local tun interface channel, and write into remote udp channel.
	wg.Add(1)
	go func() {
		wg.Done()
		for {
			data := <-rCh
			logger.Debug("Write to net", "len", len(data))
			if err := c.Write(&data); err != nil {
				logger.Error("Write to net", "error", err)
				break
			}
		}
		err := c.Close()
		if err != nil {
			logger.Error("Close crypt", "error", err)
		}
	}()

	// read data from tun into rCh channel.
	wg.Add(1)
	go func() {
		wg.Done()
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
		wg.Done()
		for {
			buf := <-wCh
			if _, err := tun.Write(buf); err != nil {
				panic(err)
			}
			logger.Debug("Write into tun", "len", len(buf))
		}
	}()
	wg.Wait()
}
