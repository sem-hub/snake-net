package transport

import (
	"errors"
	"net"
	"strconv"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/songgao/water"
)

const BUFSIZE = 4000

type TcpTransport struct {
	TransportData
	listen     net.Listener
	clientConn *net.TCPConn
	//	serverConnPool []*net.TCPConn
	packet []byte
	buf    []byte
	index  int
	len    int
}

func NewTcpTransport(c *configs.Config) *TcpTransport {
	var t = NewTransport(c)
	//return &TcpTransport{*t, nil, nil, []*net.TCPConn{}, []byte{}, make([]byte, BUFSIZE), 0, 0}
	return &TcpTransport{*t, nil, nil, []byte{}, make([]byte, BUFSIZE), 0, 0}
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
		tcp.clientConn = conn
	}

	return nil
}

func (tcp *TcpTransport) WaitConnection(c *configs.Config, tun *water.Interface,
	callback func(Transport, net.Conn, *water.Interface)) error {
	logger := configs.GetLogger()
	logger.Debug("Listen for connection")
	listen, err := net.Listen("tcp", c.LocalAddr+":"+c.LocalPort)
	if err != nil {
		return err
	}

	conn, err := listen.Accept()
	if err != nil {
		return err
	}

	tcpconn := conn.(*net.TCPConn)
	tcpconn.SetNoDelay(true)
	tcpconn.SetLinger(0)
	callback(tcp, tcpconn, tun)
	err = listen.Close()
	if err != nil {
		logger.Error("listen", err)
	}
	return nil
}

func (tcp *TcpTransport) Send(conn net.Conn, msg *Message) error {
	//logger := configs.GetLogger()
	tcpconn := conn.(*net.TCPConn)

	n := len(*msg)
	buf := make([]byte, n+2)
	buf[0] = byte(n >> 8)
	buf[1] = byte(n)
	copy(buf[2:], *msg)
	//logger.Debug("Send data (+2)", "len", n)
	l, err := tcpconn.Write(buf)
	if err != nil {
		return err
	}
	if l < n+2 {
		return errors.New("TCP sent less data: " + strconv.Itoa(l) + " != " + strconv.Itoa(n))
	}
	return nil
}

func (tcp *TcpTransport) Receive(conn net.Conn) (*Message, int, error) {
	logger := configs.GetLogger()
	tcpconn := conn.(*net.TCPConn)
	tcp.packet = make([]byte, BUFSIZE)
	b := make([]byte, 2)
	l := 0
	var err error
	if tcp.len == 0 {
		l, err = tcpconn.Read(b)
		if err != nil {
			return nil, 0, err
		}
		if l != 2 {
			if l == 0 {
				return nil, 0, errors.New("TCP connection closed (first read)")
			} else {
				return nil, 0, errors.New("TCP read less data")
			}
		}
		//logger.Debug("Read data", "len", l)
	} else {
		b = tcp.buf[:2]
	}
	n := int(b[0])<<8 | int(b[1])
	if n > BUFSIZE {
		return nil, 0, errors.New("TCP message too long")
	}

	l = 0
	if tcp.len < n {
		l, err = tcpconn.Read(tcp.buf[:n])
		if err != nil {
			return nil, 0, err
		}
		//logger.Debug("Read data", "len", l)
		for l < n {
			l1, err := tcpconn.Read(tcp.buf[l:n])
			if err != nil {
				return nil, 0, err
			}
			if l1 == 0 {
				return nil, 0, errors.New("TCP connection closed")
			}
			//logger.Debug("Read data (continue)", "len", l1)
			l += l1
		}
		tcp.len += l
	}
	copy(tcp.packet[:], tcp.buf[:n])
	if tcp.len > n {
		tcp.buf = tcp.buf[n : tcp.len-n]
		tcp.len = tcp.len - n
		logger.Debug("Buffer moved", "len", tcp.len)
	} else {
		tcp.len = 0
	}
	logger.Debug("Got data", "len", n, "from", tcpconn.RemoteAddr())
	msg := Message(tcp.buf[tcp.index:l])
	return &msg, l, nil
}

func (tcp *TcpTransport) Close() error {
	if tcp.clientConn != nil {
		err := tcp.clientConn.Close()
		if err != nil {
			return err
		}
	}

	return nil
}

func (tcp *TcpTransport) GetClientConn() net.Conn {
	return tcp.clientConn
}
