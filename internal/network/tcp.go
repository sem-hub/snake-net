package network

import (
	"errors"
	"fmt"
	"net"

	"github.com/sem-hub/snake-net/internal/configs"
)

type TcpTransport struct {
	TransportData
	listen net.Listener
	conn   *net.TCPConn
}

func NewTcpTransport(c *configs.Config) *TcpTransport {
	var t = NewTransport(c)
	return &TcpTransport{*t, nil, nil}
}

func (tcp *TcpTransport) Init(c *configs.Config) error {
	if c.Mode != "server" {
		tcpServer, err := net.ResolveTCPAddr("tcp", c.RemoteAddr+":"+c.RemotePort)
		if err != nil {
			return err
		}
		conn, err := net.DialTCP("tcp", nil, tcpServer)
		if err != nil {
			return err
		}
		tcp.conn = conn
	}

	return nil
}

func (tcp *TcpTransport) WaitConnection(c *configs.Config, callback func(Transport, net.Conn)) error {
	fmt.Println("Listen for connection")
	listen, err := net.Listen("tcp", c.LocalAddr+":"+c.LocalPort)
	if err != nil {
		return err
	}

	conn, err := listen.Accept()
	if err != nil {
		return err
	}
	tcpconn := conn.(*net.TCPConn)
	callback(tcp, tcpconn)
	err = listen.Close()
	if err != nil {
		fmt.Println(err)
	}
	return nil
}

func (tcp *TcpTransport) Send(conn net.Conn, msg *Message) error {
	tcpconn := conn.(*net.TCPConn)

	l, err := tcpconn.Write([]byte(*msg))
	if err != nil {
		return err
	}
	if l != len(*msg) {
		return errors.New("TCP sent less data")
	}
	return nil
}

func (tcp *TcpTransport) Receive(conn net.Conn) (*Message, int, error) {
	tcpconn := conn.(*net.TCPConn)
	b := make([]byte, 1500)
	l, err := tcpconn.Read(b)
	if err != nil {
		return nil, 0, err
	}
	return &b, l, nil
}

func (tcp *TcpTransport) Close() error {
	if tcp.conn == nil {
		return nil
	}
	err := tcp.conn.Close()
	if err != nil {
		return err
	}

	return nil
}

func (tcp *TcpTransport) GetClientConn() net.Conn {
	return tcp.conn
}
