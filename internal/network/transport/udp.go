package transport

import (
	"errors"
	"log"
	"net"

	"github.com/sem-hub/snake-net/internal/configs"
)

type UdpTransport struct {
	td         *TransportData
	mainConn   *net.UDPConn
	clientAddr map[string]net.Addr
}

func NewUdpTransport(c *configs.Config) *UdpTransport {
	var t = NewTransport(c)
	return &UdpTransport{t, nil, make(map[string]net.Addr)}
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
	}

	return nil
}

func (udp *UdpTransport) Listen(c *configs.Config, callback func(Transport, net.Conn, net.Addr)) error {
	logger := configs.GetLogger()

	udpLocal, err := net.ResolveUDPAddr("udp", c.LocalAddr+":"+c.LocalPort)
	if err != nil {
		return err
	}

	log.Printf("Listen: %s\n", c.LocalAddr+":"+c.LocalPort)
	for {
		conn, err := net.ListenUDP("udp", udpLocal)
		if err != nil {
			return err
		}
		udp.mainConn = conn

		for {
			_, l, addr, err := udp.Receive(conn)
			if err != nil {
				logger.Error("First client read", "error", err)
				break
			}
			if l == 0 {
				go callback(udp, conn, addr)
			}
		}
		conn.Close()
	}
	//return nil
}

func (udp *UdpTransport) Send(addr net.Addr, conn net.Conn, msg *Message) error {
	udpconn := conn.(*net.UDPConn)
	n := len(*msg)

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

func (udp *UdpTransport) Receive(conn net.Conn) (Message, int, net.Addr, error) {
	udpconn := conn.(*net.UDPConn)

	b := make([]byte, BUFSIZE)
	l, fromAddr, err := udpconn.ReadFrom(b)
	if err != nil {
		return nil, 0, nil, err
	}

	configs.GetLogger().Debug("UDP ReadFrom", "len", l, "fromAddr", fromAddr)
	// if we first met this client
	if _, ok := udp.clientAddr[fromAddr.String()]; !ok {
		// Listen() will call callback() for the new client
		udp.clientAddr[fromAddr.String()] = fromAddr
		return nil, 0, fromAddr, nil
	}
	udp.clientAddr[fromAddr.String()] = fromAddr

	//configs.GetLogger().Debug("Got data", "len", l, "from", fromAddr)
	return b, l, fromAddr, nil
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
