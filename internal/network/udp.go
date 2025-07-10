package network

import (
	"errors"
	"fmt"
	"net"

	"github.com/sem-hub/snake-net/internal/configs"
)

type UdpTransport struct {
	TransportData
	conn     *net.UDPConn
	readFrom net.Addr
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
		udp.conn = conn.(*net.UDPConn)
		if err != nil {
			return err
		}
	}

	return nil
}

func (udp *UdpTransport) WaitConnection(c *configs.Config, callback func(Transport, net.Conn)) error {
	udpLocal, err := net.ResolveUDPAddr("udp", c.LocalAddr+":"+c.LocalPort)
	if err != nil {
		return err
	}

	fmt.Printf("Listen: %s\n", c.LocalAddr+":"+c.LocalPort)
	conn, err := net.ListenUDP("udp", udpLocal)
	if err != nil {
		return err
	}
	udp.conn = conn
	callback(udp, conn)
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
	udpconn := conn.(*net.UDPConn)
	b := make([]byte, 1500)
	l, addr, err := udpconn.ReadFrom(b)
	udp.readFrom = addr
	if err != nil {
		return nil, 0, err
	}
	fmt.Printf("Got data from %v\n", addr)
	return &b, l, nil
}

func (udp *UdpTransport) Close() error {
	if udp.conn == nil {
		return nil
	}
	err := udp.conn.Close()
	if err != nil {
		return err
	}
	return nil
}

func (udp *UdpTransport) GetClientConn() net.Conn {
	return udp.conn
}
