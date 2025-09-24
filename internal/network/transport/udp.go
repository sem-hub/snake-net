package transport

import (
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"
)

type UdpTransport struct {
	TransportData
	mainConn      *net.UDPConn
	clientAddr    map[string]net.Addr
	packetBuf     map[string][][]byte
	packetBufLock *sync.Mutex
}

func NewUdpTransport(logger *slog.Logger) *UdpTransport {
	return &UdpTransport{TransportData: *NewTransport(logger), mainConn: nil, clientAddr: make(map[string]net.Addr),
		packetBuf: make(map[string][][]byte), packetBufLock: &sync.Mutex{}}
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
	callback func(Transport, net.Conn, net.Addr)) error {

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

func (udp *UdpTransport) runReadLoop(callback func(Transport, net.Conn, net.Addr)) error {
	for {
		newConnection := false
		buf := make([]byte, NETBUFSIZE)
		l, addr, err := udp.mainConn.ReadFrom(buf)
		if err != nil {
			logger.Error("UDP ReadFrom", "error", err)
			break
		}

		udp.packetBufLock.Lock()
		if _, ok := udp.clientAddr[addr.String()]; !ok {
			newConnection = true
			udp.clientAddr[addr.String()] = addr
		} else {
			newConnection = false
		}
		udp.packetBuf[addr.String()] = append(udp.packetBuf[addr.String()], buf[:l])
		udp.packetBufLock.Unlock()
		logger.Debug("UDP Listen put into buffer", "len", l, "from", addr, "packetBuf len", len(udp.packetBuf[addr.String()]))

		if newConnection {
			if callback == nil {
				logger.Error("UDP Listen: No callback for client connection")
				continue
			}
			go callback(udp, udp.mainConn, addr)
		}
	}
	return nil
}

func (udp *UdpTransport) Send(addr net.Addr, conn net.Conn, msg *Message) error {
	udpconn := conn.(*net.UDPConn)
	n := len(*msg)

	logger.Debug("UDP Send data", "len", n, "to", addr)
	l, err := udpconn.WriteTo(*msg, addr)
	if err != nil {
		return err
	}
	if l != n {
		return errors.New("UDP sent less data")
	}
	return nil
}

func (udp *UdpTransport) Receive(conn net.Conn, addr net.Addr) (Message, int, net.Addr, error) {
	// If we have buffered packets for this addr
	var bufArray [][]byte

	logger.Debug("UDP Receive waiting for data", "fromAddr", addr)
	for {
		udp.packetBufLock.Lock()
		var ok bool
		if bufArray, ok = udp.packetBuf[addr.String()]; ok && len(bufArray) > 0 {
			udp.packetBufLock.Unlock()
			break
		}
		udp.packetBufLock.Unlock()
		time.Sleep(1 * time.Millisecond)
	}
	udp.packetBufLock.Lock()
	// Refresh bufArray in case it changed
	bufArray = udp.packetBuf[addr.String()]
	buf := bufArray[0]
	//logger.Debug("UDP ReadFrom (from buf)", "len", len(buf), "fromAddr", addr)

	if len(bufArray) > 1 {
		udp.packetBuf[addr.String()] = bufArray[1:]
	} else {
		delete(udp.packetBuf, addr.String())
	}
	udp.packetBufLock.Unlock()
	return buf, len(buf), addr, nil
}

func (udp *UdpTransport) CloseClient(addr net.Addr) error {
	udp.packetBufLock.Lock()
	defer udp.packetBufLock.Unlock()
	delete(udp.clientAddr, addr.String())
	delete(udp.packetBuf, addr.String())
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

func (udp *UdpTransport) GetMainConn() net.Conn {
	return udp.mainConn
}
