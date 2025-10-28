package transport

import (
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"
)

type UdpTransport struct {
	TransportData
	mainConn      *net.UDPConn
	clientAddr    map[netip.AddrPort]net.Addr
	packetBuf     map[netip.AddrPort][][]byte
	packetBufLock *sync.Mutex
}

func NewUdpTransport(logger *slog.Logger) *UdpTransport {
	return &UdpTransport{TransportData: *NewTransport(logger), mainConn: nil, clientAddr: make(map[netip.AddrPort]net.Addr),
		packetBuf: make(map[netip.AddrPort][][]byte), packetBufLock: &sync.Mutex{}}
}

func (udp *UdpTransport) GetName() string {
	return "udp"
}

func (udp *UdpTransport) GetType() string {
	return "datagram"
}

func (udp *UdpTransport) IsEncrypted() bool {
	return false
}

func (udp *UdpTransport) Init(mode string, rAddr string, rPort string, lAddr string, lPort string,
	callback func(Transport, netip.AddrPort)) error {

	if mode != "server" {
		conn, err := net.ListenPacket("udp", ":0")
		if err != nil {
			return err
		}
		udp.mainConn = conn.(*net.UDPConn)
	} else {
		udpLocal, err := net.ResolveUDPAddr("udp", lAddr+":"+lPort)
		if err != nil {
			return err
		}

		conn, err := net.ListenUDP("udp", udpLocal)
		if err != nil {
			return err
		}
		udp.mainConn = conn
	}
	go udp.runReadLoop(callback)

	return nil
}

func (udp *UdpTransport) runReadLoop(callback func(Transport, netip.AddrPort)) error {
	for {
		newConnection := false
		buf := make([]byte, NETBUFSIZE)
		l, addr, err := udp.mainConn.ReadFrom(buf)
		if err != nil {
			logger.Error("UDP ReadFrom", "error", err)
			break
		}

		netipAddrPort := netip.MustParseAddrPort(addr.String()) // XXX

		udp.packetBufLock.Lock()
		if _, ok := udp.clientAddr[netipAddrPort]; !ok {
			newConnection = true
			udp.clientAddr[netipAddrPort] = addr
		} else {
			newConnection = false
		}
		udp.packetBuf[netipAddrPort] = append(udp.packetBuf[netipAddrPort], buf[:l])
		udp.packetBufLock.Unlock()
		logger.Debug("UDP Listen put into buffer", "len", l, "from", addr, "len(packetBuf)", len(udp.packetBuf[netipAddrPort]))

		if newConnection {
			if callback == nil {
				logger.Error("UDP Listen: No callback for client connection")
				continue
			}
			go callback(udp, netipAddrPort)
		}
	}
	return nil
}

func (udp *UdpTransport) Send(addrPort netip.AddrPort, msg *Message) error {
	n := len(*msg)

	logger.Debug("UDP Send data", "len", n, "to", addrPort.String())
	udpAddr := &net.UDPAddr{
		IP:   addrPort.Addr().AsSlice(), // Преобразуем в net.IP
		Port: int(addrPort.Port()),      // uint16 -> int
	}
	l, err := udp.mainConn.WriteTo(*msg, udpAddr)
	if err != nil {
		return err
	}
	if l != n {
		return errors.New("UDP sent less data")
	}
	return nil
}

func (udp *UdpTransport) Receive(addrPort netip.AddrPort) (Message, int, error) {
	// If we have buffered packets for this addr
	var bufArray [][]byte

	logger.Debug("UDP Receive waiting for data", "fromAddr", addrPort.String())
	for {
		udp.packetBufLock.Lock()
		var ok bool
		if bufArray, ok = udp.packetBuf[addrPort]; ok && len(bufArray) > 0 {
			udp.packetBufLock.Unlock()
			break
		}
		udp.packetBufLock.Unlock()
		time.Sleep(1 * time.Millisecond)
	}
	udp.packetBufLock.Lock()
	// Refresh bufArray in case it changed
	bufArray = udp.packetBuf[addrPort]
	buf := bufArray[0]
	//logger.Debug("UDP ReadFrom (from buf)", "len", len(buf), "fromAddr", addrPort.String())

	if len(bufArray) > 1 {
		udp.packetBuf[addrPort] = bufArray[1:]
	} else {
		delete(udp.packetBuf, addrPort)
	}
	udp.packetBufLock.Unlock()
	return buf, len(buf), nil
}

func (udp *UdpTransport) CloseClient(addrPort netip.AddrPort) error {
	udp.packetBufLock.Lock()
	defer udp.packetBufLock.Unlock()
	delete(udp.clientAddr, addrPort)
	delete(udp.packetBuf, addrPort)
	return nil
}

func (udp *UdpTransport) Close() error {
	if udp.mainConn != nil {
		err := udp.mainConn.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
