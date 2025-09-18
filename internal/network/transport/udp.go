package transport

import (
	"errors"
	"log/slog"
	"net"
	"sync"
)

type UdpTransport struct {
	TransportData
	mainConn      *net.UDPConn
	clientAddr    map[string]net.Addr
	packetBuf     map[string][][]byte
	packetBufLock *sync.Mutex
	bufferReady   bool
}

func NewUdpTransport(logger *slog.Logger) *UdpTransport {
	return &UdpTransport{TransportData: *NewTransport(logger), mainConn: nil, clientAddr: make(map[string]net.Addr),
		packetBuf: make(map[string][][]byte), packetBufLock: &sync.Mutex{}, bufferReady: false}
}

func (udp *UdpTransport) GetName() string {
	return "udp"
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
			logger.Error("First client read", "error", err)
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
		udp.bufferReady = true
		udp.packetBufLock.Unlock()
		logger.Debug("Listen buffer read", "len", l, "from", addr)

		if newConnection {
			if callback == nil {
				logger.Error("Listen: No callback for client connection")
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

	logger.Debug("Send data UDP", "len", n, "to", addr)
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
	for {
		udp.packetBufLock.Lock()
		var ok bool
		if bufArray, ok = udp.packetBuf[addr.String()]; udp.bufferReady && ok {
			udp.packetBufLock.Unlock()
			break
		}
		udp.packetBufLock.Unlock()
	}
	udp.packetBufLock.Lock()
	buf := bufArray[0]
	logger.Debug("UDP ReadFrom (from buf)", "len", len(buf), "fromAddr", addr)
	bufArray = bufArray[1:]

	if len(bufArray) > 0 {
		udp.packetBuf[addr.String()] = bufArray
	} else {
		delete(udp.packetBuf, addr.String())
	}
	udp.bufferReady = len(udp.packetBuf) > 0
	udp.packetBufLock.Unlock()
	return buf, len(buf), addr, nil
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
