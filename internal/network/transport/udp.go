package transport

import (
	"errors"
	"net"
	"sync"

	"github.com/sem-hub/snake-net/internal/configs"
)

type UdpTransport struct {
	td            *TransportData
	mainConn      *net.UDPConn
	clientAddr    map[string]net.Addr
	packetBuf     map[string][][]byte
	packetBufLock *sync.Mutex
	bufferReady   bool
	listening     bool
	listenReady   chan bool
}

func NewUdpTransport(c *configs.Config) *UdpTransport {
	var t = NewTransport(c)
	return &UdpTransport{t, nil, make(map[string]net.Addr), make(map[string][][]byte), &sync.Mutex{}, false,
		false, make(chan bool)}
}

func (udp *UdpTransport) GetName() string {
	return "udp"
}

func (udp *UdpTransport) Init(c *configs.Config) error {
	/*udpServer, err := net.ResolveUDPAddr("udp", c.RemoteAddr+":"+c.RemotePort)
	if err != nil {
		return err
	}*/

	if c.Mode != "server" {
		conn, err := net.ListenPacket("udp", ":0")
		if err != nil {
			return err
		}
		udp.mainConn = conn.(*net.UDPConn)
	} else {
		udpLocal, err := net.ResolveUDPAddr("udp", c.LocalAddr+":"+c.LocalPort)
		if err != nil {
			return err
		}

		conn, err := net.ListenUDP("udp", udpLocal)
		if err != nil {
			return err
		}
		udp.mainConn = conn
	}

	return nil
}

func (udp *UdpTransport) Listen(c *configs.Config, callback func(Transport, net.Conn, net.Addr)) error {
	logger := configs.GetLogger()

	for {
		newConnection := false
		buf := make([]byte, 2048)
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

	if !udp.listening {
		// In client mode we only have one connection
		// so we need to start listening for incoming packets
		go udp.Listen(configs.GetConfig(), nil)
	}

	configs.GetLogger().Debug("Send data UDP", "len", n, "to", addr)
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
	configs.GetLogger().Debug("UDP ReadFrom (from buf)", "len", len(buf), "fromAddr", addr)
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
