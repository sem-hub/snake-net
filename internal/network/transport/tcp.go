package transport

import (
	"errors"
	"net"
	"strconv"

	"github.com/sem-hub/snake-net/internal/configs"
)

const BUFSIZE = 4000

type TcpTransport struct {
	td       *TransportData
	listen   net.Listener
	mainConn *net.TCPConn
	conn     map[string]net.TCPConn
}

func NewTcpTransport(c *configs.Config) *TcpTransport {
	var t = NewTransport(c)
	return &TcpTransport{t, nil, nil, make(map[string]net.TCPConn)}
}

func (tcp *TcpTransport) GetName() string {
	return "tcp"
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
		tcp.mainConn = conn
	}

	return nil
}

func (tcp *TcpTransport) Listen(c *configs.Config, callback func(Transport, net.Conn, net.Addr)) error {
	logger := configs.GetLogger()
	logger.Debug("Listen for connection")
	listen, err := net.Listen("tcp", c.LocalAddr+":"+c.LocalPort)
	if err != nil {
		return err
	}

	for {
		conn, err := listen.Accept()
		if err != nil {
			break
		}

		tcpconn := conn.(*net.TCPConn)
		tcpconn.SetNoDelay(true)
		tcpconn.SetLinger(0)
		tcp.conn[tcpconn.RemoteAddr().String()] = *tcpconn
		go callback(tcp, tcpconn, tcpconn.RemoteAddr())
	}
	err = listen.Close()
	if err != nil {
		logger.Error("listen", "error", err)
	}
	return nil
}

func (tcp *TcpTransport) Send(addr net.Addr, conn net.Conn, buf *Message) error {
	tcpconn := conn.(*net.TCPConn)

	n := len(*buf)
	configs.GetLogger().Debug("Send data to network", "len", n)
	l, err := tcpconn.Write(*buf)
	if err != nil {
		return err
	}
	if l < n {
		return errors.New("TCP sent less data: " + strconv.Itoa(l) + " != " + strconv.Itoa(n))
	}
	return nil
}

func (tcp *TcpTransport) Receive(conn net.Conn) (Message, int, net.Addr, error) {
	tcpconn := conn.(*net.TCPConn)
	addrStr := tcpconn.RemoteAddr().String()

	b := make([]byte, BUFSIZE)
	l, err := tcpconn.Read(b)
	if err != nil {
		return nil, 0, nil, err
	}

	configs.GetLogger().Debug("Got data", "len", l, "from", addrStr)
	msg := Message(b)[:l]
	return msg, l, conn.RemoteAddr(), nil
}

func (tcp *TcpTransport) Close() error {
	if tcp.mainConn != nil {
		err := tcp.mainConn.Close()
		if err != nil {
			return err
		}
	}

	return nil
}

func (tcp *TcpTransport) GetMainConn() net.Conn {
	return tcp.mainConn
}
