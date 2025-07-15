package network

import (
	"fmt"
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
	err = netlink.LinkSetMTU(link, 1376)
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
			buf, err := c.Read()
			if err != nil {
				fmt.Println("Read packet from net error: ", err)
				// Ignore bad packet
				continue
			}
			fmt.Println("Read from net:", len(buf))
			//fmt.Printf("%x\n", buf)
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
			fmt.Println("Write to net:", len(data))
			//fmt.Printf("%x\n", data)
			if err := c.Write(&data); err != nil {
				fmt.Println("Read error: ", err)
				break
			}
		}
		err := c.Close()
		if err != nil {
			fmt.Println("Close crypt error: ", err)
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
			fmt.Printf("Read %d bytes from tun\n", n)
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
			fmt.Printf("Write %d bytes to tun\n", len(buf))
		}
	}()
	wg.Wait()
}
