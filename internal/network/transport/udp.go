package transport

import (
	"errors"
	"log"
	"net"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/songgao/water"
)

type UdpTransport struct {
	TransportData
	clientConn *net.UDPConn
	readFrom   net.Addr
}

func NewUdpTransport(c *configs.Config) *UdpTransport {
	var t = NewTransport(c)
	return &UdpTransport{*t, nil, nil}
}

func (udp *UdpTransport) Init(c *configs.Config) error {
	udpServer, err := net.ResolveUDPAddr("udp", c.RemoteAddr+":"+c.RemotePort)
	if err != nil {
		return err
	}
	udp.readFrom = udpServer

	if c.Mode != "server" {
		conn, err := net.ListenPacket("udp", ":0")
		if err != nil {
			return err
		}
		udp.clientConn = conn.(*net.UDPConn)
	}

	return nil
}

func (udp *UdpTransport) WaitConnection(c *configs.Config, tun *water.Interface,
	callback func(Transport, net.Conn, *water.Interface)) error {
	//logger := configs.GetLogger()
	udpLocal, err := net.ResolveUDPAddr("udp", c.LocalAddr+":"+c.LocalPort)
	if err != nil {
		return err
	}

	log.Printf("Listen: %s\n", c.LocalAddr+":"+c.LocalPort)
	conn, err := net.ListenUDP("udp", udpLocal)
	if err != nil {
		return err
	}
	udp.clientConn = conn
	callback(udp, conn, tun)
	conn.Close()
	return nil
}

func (udp *UdpTransport) Send(conn net.Conn, msg *Message) error {
	udpconn := conn.(*net.UDPConn)
	l, err := udpconn.WriteTo([]byte(*msg), udp.readFrom)
	if err != nil {
		return err
	}
	if l != len(*msg) {
		return errors.New("UDP sent less data")
	}
	return nil
}

func (udp *UdpTransport) Receive(conn net.Conn) (*Message, int, error) {
	logger := configs.GetLogger()
	udpconn := conn.(*net.UDPConn)
	b := make([]byte, 1500)
	l, addr, err := udpconn.ReadFrom(b)
	udp.readFrom = addr
	if err != nil {
		return nil, 0, err
	}
	logger.Debug("Got data", "len", l, "from", addr)
	return &b, l, nil
}

func (udp *UdpTransport) Close() error {
	if udp.clientConn != nil {
		err := udp.clientConn.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func (udp *UdpTransport) GetClientConn() net.Conn {
	return udp.clientConn
}
