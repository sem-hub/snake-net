package network

import (
	"errors"
	"log"
	"log/slog"
	"net/netip"
	"runtime"

	"github.com/sem-hub/snake-net/internal/clients"
	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/interfaces"
	"github.com/sem-hub/snake-net/internal/utils"
	"golang.zx2c4.com/wireguard/tun"
)

const DefaultMTU = 1420

type TunInterface struct {
	interfaces.TunInterface

	tunDev    tun.Device
	name      string
	cidrs     []utils.Cidr
	mtu       int
	logger    *slog.Logger
	readBuffs [][]byte
}

var tunIf *TunInterface

func NewTUN(name string, cidrs []utils.Cidr, mtu int) (interfaces.TunInterface, error) {
	logger := configs.InitLogger("tun")

	if mtu == 0 {
		mtu = DefaultMTU
	}

	iface := TunInterface{
		tunDev:    nil,
		name:      name,
		cidrs:     make([]utils.Cidr, 0),
		mtu:       mtu,
		logger:    logger,
		readBuffs: make([][]byte, 0),
	}

	var err error
	iface.cidrs = append(iface.cidrs, cidrs...)

	iface.tunDev, err = tun.CreateTUN(name, mtu)
	if err != nil {
		log.Fatalln(err)
	}

	iface.name, err = iface.tunDev.Name()
	if err != nil {
		log.Fatalln("Get tun name")
	}
	logger.Info("Interface", "name", iface.name)
	if err := iface.setUpInterface(); err != nil {
		logger.Error("Set up interface", "err", err)
		return nil, err
	}

	tunIf = &iface
	return &iface, nil
}

// Read from TUN and pass to client(s)
// It blocks main thread. Exit here, exit main.
func ProcessTun() {
	if tunIf == nil {
		log.Fatal("TUN interface not initialized")
	}
	for {
		buf, err := tunIf.ReadTun()
		if err != nil {
			tunIf.logger.Error("ReadTun", "error", err)
			break
		}
		tunIf.logger.Debug("TUN: Read from tun", "len", len(buf))
		// send to all clients except the sender
		clients.Route(netip.AddrPort{}, buf)
	}
}

func (tunIf *TunInterface) ReadTun() ([]byte, error) {
	if len(tunIf.readBuffs) > 0 {
		buf := tunIf.readBuffs[0]
		tunIf.readBuffs = tunIf.readBuffs[1:]
		tunIf.logger.Debug("TUN: Read from tun (from buffer)", "len", len(buf))
		return buf, nil
	}

	// Allocate batch buffers
	batchSize := 64
	bufs := make([][]byte, batchSize)
	sizes := make([]int, batchSize)
	for i := 0; i < batchSize; i++ {
		bufs[i] = make([]byte, tunIf.mtu+100)
		sizes[i] = tunIf.mtu
	}

	var count int
	var err error

	if count, err = tunIf.tunDev.Read(bufs, sizes, 0); err != nil {
		return nil, err
	}
	if count != 1 {
		tunIf.logger.Debug("TUN: Read multiple buffers", "count", count)
		tunIf.readBuffs = append(tunIf.readBuffs, bufs[1:count]...)
	}
	buf := bufs[0][:sizes[0]]
	tunIf.logger.Debug("TUN: Read from tun", "count", count, "sizes", sizes[0])
	return buf, nil
}

func (tunIf *TunInterface) WriteTun(buf []byte) error {
	if tunIf == nil {
		slog.Debug("WriteTun: did not initialized yet")
		return errors.New("did not initialized")
	}
	bufs := make([][]byte, 1)
	offset := 0
	if runtime.GOOS == "linux" {
		offset = 16
	}
	bufs[0] = make([]byte, len(buf)+offset)
	copy(bufs[0][offset:], buf)
	tunIf.logger.Debug("TUN: Write into tun", "len", len(buf))
	if _, err := tunIf.tunDev.Write(bufs, offset); err != nil {
		return err
	}
	return nil
}

func (tunIf *TunInterface) Close() {
	tunIf.logger.Info("TUN Interface Close")
	// Try to close underlying tun device to unblock Read
	if tunIf.tunDev != nil {
		err := tunIf.tunDev.Close()
		if err != nil {
			tunIf.logger.Error("Close tun device", "error", err)
		}
	}
}
