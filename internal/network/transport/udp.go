package transport

import (
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
)

type UdpTransport struct {
	TransportData
	mainConn      *net.UDPConn
	clientAddr    map[netip.AddrPort]bool     // This field is used to track active clients
	packetBuf     map[netip.AddrPort][][]byte // A client buffer removed when empty. Track connections with clientAddr
	packetBufLock *sync.Mutex
	packetBufCond *sync.Cond
}

func NewUdpTransport(logger *slog.Logger) *UdpTransport {
	udpTransport := UdpTransport{
		TransportData: *NewTransport(logger),
		mainConn:      nil,
		clientAddr:    make(map[netip.AddrPort]bool),
		packetBuf:     make(map[netip.AddrPort][][]byte),
		packetBufLock: &sync.Mutex{},
	}
	udpTransport.packetBufCond = sync.NewCond(udpTransport.packetBufLock)
	return &udpTransport
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

func (udp *UdpTransport) Init(mode string, rAddrPort string, lAddrPort string,
	callback func(Transport, netip.AddrPort)) error {

	if mode == "server" {
		udpLocal, err := net.ResolveUDPAddr("udp", lAddrPort)
		if err != nil {
			return err
		}
		logger.Debug("Listen for connection", "on", lAddrPort)
		conn, err := net.ListenUDP("udp", udpLocal)
		if err != nil {
			return err
		}
		udp.mainConn = conn
	} else {
		conn, err := net.ListenPacket("udp", ":0")
		if err != nil {
			return err
		}
		udp.mainConn = conn.(*net.UDPConn)
	}
	go udp.runReadLoop(callback)

	return nil
}

func (udp *UdpTransport) runReadLoop(callback func(Transport, netip.AddrPort)) error {
	for {
		newConnection := false
		buf := make([]byte, NETBUFSIZE)
		l, addrPort, err := udp.mainConn.ReadFromUDPAddrPort(buf)
		if err != nil {
			logger.Error("UDP ReadFrom", "error", err)
			break
		}

		// We must use unmaped address for consistency
		addrPort = netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port())

		logger.Debug("UDP read from connection", "len", l, "from", addrPort.String())

		udp.packetBufLock.Lock()
		if _, ok := udp.clientAddr[addrPort]; !ok {
			newConnection = true
			udp.clientAddr[addrPort] = true
		} else {
			newConnection = false
		}
		udp.packetBuf[addrPort] = append(udp.packetBuf[addrPort], buf[:l])
		udp.packetBufLock.Unlock()
		// Ready to process
		udp.packetBufCond.Broadcast()
		logger.Debug("UDP put into buffer", "len", l, "from", addrPort.String(), "len(packetBuf)", len(udp.packetBuf[addrPort]))

		if newConnection {
			if callback == nil {
				logger.Error("UDP Listen: No callback for client connection")
				continue
			}
			go callback(udp, addrPort)
		}
	}
	return nil
}

func (udp *UdpTransport) Send(addrPort netip.AddrPort, msg *Message) error {
	n := len(*msg)

	logger.Debug("UDP Send data", "len", n, "to", addrPort.String())
	l, err := udp.mainConn.WriteToUDPAddrPort(*msg, addrPort)
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
	udp.packetBufLock.Lock()
	var ok bool
	for bufArray, ok = udp.packetBuf[addrPort]; !ok || len(bufArray) == 0; bufArray, ok = udp.packetBuf[addrPort] {
		udp.packetBufCond.Wait()
	}
	// Refresh bufArray in case it changed
	bufArray = udp.packetBuf[addrPort]
	buf := bufArray[0]
	logger.Debug("UDP ReadFrom (from buf)", "len", len(buf), "fromAddr", addrPort.String())

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
	// Unblock any Receive waiting on this client
	udp.packetBufCond.Broadcast()
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
