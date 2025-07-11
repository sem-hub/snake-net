package network

import (
	"fmt"
	"log"
	"sync"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/crypt"
	"github.com/songgao/water"
	"github.com/songgao/water/waterutil"
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
	wg := sync.WaitGroup{}
	// local tun interface read and write channel.
	rCh := make(chan []byte)
	wCh := make(chan []byte)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			buff, err := c.Read()
			if err != nil {
				panic(err)
			}
			fmt.Println("Read from net:", len(buff))
			//fmt.Printf("%x\n", buff)
			// write into local tun interface channel.
			wCh <- buff
		}
	}()
	// read from local tun interface channel, and write into remote udp channel.
	wg.Add(1)
	go func() {
		wg.Done()
		for {
			data := <-rCh
			fmt.Println("Write to net:", len(data))
			//fmt.Printf("%x\n", data)
			if err := c.Write(&data); err != nil {
				panic(err)
			}
		}
	}()

	// read data from tun into rCh channel.
	wg.Add(1)
	go func() {
		wg.Done()
		for {
			buff := make([]byte, 1522)
			var n int
			var err error

			if n, err = tun.Read(buff); err != nil {
				panic(err)
			}
			// Ignore not IPv4 packet for now
			if !waterutil.IsIPv4(buff) {
				continue
			}
			buff = buff[:n]
			fmt.Printf("Read %d bytes from tun\n", n)
			rCh <- buff
		}
	}()
	// write data into tun from wCh channel.
	wg.Add(1)
	go func() {
		wg.Done()
		for {
			buff := <-wCh
			if _, err := tun.Write(buff); err != nil {
				panic(err)
			}
			fmt.Printf("Write %d bytes to tun\n", len(buff))
		}
	}()
	wg.Wait()
}
