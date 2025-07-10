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
	err = netlink.LinkSetUp(link)
	if err != nil {
		return nil, err
	}

	return ifce, nil
}

func ProcessTun(c *crypt.Secrets, tun *water.Interface) {
	wg := sync.WaitGroup{}
	// local tun interface read and write channel.
	rCh := make(chan []byte, 1500)
	wCh := make(chan []byte, 1500)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			buff, err := c.Read()
			if err != nil {
				panic(err)
			}
			// log.Println("tun<-conn:", n)
			// write into local tun interface channel.
			wCh <- buff[:len(buff)]
		}
	}()
	// read from local tun interface channel, and write into remote udp channel.
	wg.Add(1)
	go func() {
		wg.Done()
		for {
			select {
			case data := <-rCh:
				if err := c.Write(&data); err != nil {
					panic(err)
					// }
				}

			}
		}
	}()

	// read data from tun into rCh channel.
	wg.Add(1)
	go func() {
		wg.Done()
		buff := make([]byte, 1500)
		var n int
		var err error
		if n, err = tun.Read(buff); err != nil {
			panic(err)
		}
		rCh <- buff[:n]
	}()
	// write data into tun from wCh channel.
	wg.Add(1)
	go func() {
		wg.Done()
		buff := <-wCh
		if _, err := tun.Write(buff); err != nil {
			panic(err)
		}
	}()
	wg.Wait()
}
