package transport

import (
	"errors"
	"net"
	"net/netip"
	"sync"
)

type UdpTransport struct {
	TransportData
	mainConn         *net.UDPConn
	connectedClients map[netip.AddrPort]bool     // This field is used to track active clients.
	packetBuf        map[netip.AddrPort][][]byte // A client buffer removed when empty. Track connections with field above.
	packetBufLock    *sync.Mutex
	packetBufCond    *sync.Cond
	hasError         bool
}

func NewUdpTransport() *UdpTransport {
	udpTransport := UdpTransport{
		TransportData:    *NewTransport(),
		mainConn:         nil,
		connectedClients: make(map[netip.AddrPort]bool),
		packetBuf:        make(map[netip.AddrPort][][]byte),
		packetBufLock:    &sync.Mutex{},
		hasError:         false,
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
		udp.logger.Info("Listen for connection", "on", lAddrPort)
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
			udp.logger.Error("UDP ReadFrom", "error", err)
			udp.hasError = true
			udp.packetBufCond.Broadcast()
			break
		}

		// We must use unmaped address for consistency
		addrPort = netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port())

		udp.logger.Debug("UDP read from connection", "len", l, "from", addrPort.String())

		udp.packetBufLock.Lock()
		if _, ok := udp.connectedClients[addrPort]; !ok {
			newConnection = true
			udp.connectedClients[addrPort] = true
		} else {
			newConnection = false
		}
		udp.packetBuf[addrPort] = append(udp.packetBuf[addrPort], buf[:l])
		udp.packetBufLock.Unlock()
		// Ready to process
		udp.packetBufCond.Broadcast()
		udp.logger.Debug("UDP put into buffer", "len", l, "from", addrPort.String(), "len(packetBuf)", len(udp.packetBuf[addrPort]))

		if newConnection {
			if callback == nil {
				udp.logger.Debug("UDP Listen: No callback for client connection")
				continue
			}
			go callback(udp, addrPort)
		}
	}
	udp.logger.Debug("UDP runReadLoop returns")
	return nil
}

func (udp *UdpTransport) Send(addrPort netip.AddrPort, msg *Message) error {
	n := len(*msg)

	udp.logger.Debug("UDP Send data", "len", n, "to", addrPort.String())
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

	udp.logger.Debug("UDP Receive waiting for data", "fromAddr", addrPort.String())
	udp.packetBufLock.Lock()
	for {
		var ok bool
		// If we don't have data in buffer for the client, wait for them
		bufArray, ok = udp.packetBuf[addrPort]
		// If transport-level error happened
		if udp.hasError {
			break
		}
		// If we have buffered packets -> proceed
		if ok && len(bufArray) > 0 {
			break
		}
		udp.packetBufCond.Wait()
	}
	if udp.hasError {
		udp.packetBufLock.Unlock()
		return nil, 0, errors.New("UDP transport error happened")
	}
	// Refresh bufArray in case it changed
	bufArray = udp.packetBuf[addrPort]
	buf := bufArray[0]
	udp.logger.Debug("UDP ReadFrom (from buf)", "len", len(buf), "fromAddr", addrPort.String())

	if len(bufArray) > 1 {
		udp.packetBuf[addrPort] = bufArray[1:]
	} else {
		delete(udp.packetBuf, addrPort)
	}
	udp.packetBufLock.Unlock()
	return buf, len(buf), nil
}

func (udp *UdpTransport) CloseClient(addrPort netip.AddrPort) error {
	udp.logger.Debug("UDP CloseClient", "address", addrPort)
	udp.packetBufLock.Lock()
	// Unblock any Receive waiting on this client
	udp.packetBufCond.Broadcast()
	delete(udp.connectedClients, addrPort)
	delete(udp.packetBuf, addrPort)
	udp.packetBufLock.Unlock()
	return nil
}

func (udp *UdpTransport) Close() error {
	udp.logger.Info("UDP Transport Close")
	if udp.mainConn != nil {
		err := udp.mainConn.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
