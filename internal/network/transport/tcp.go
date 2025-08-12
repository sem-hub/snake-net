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
	td         *TransportData
	listen     net.Listener
	clientConn *net.TCPConn
	conn       map[string]net.TCPConn
	buf        map[string][]byte
	len        map[string]int
}

func NewTcpTransport(c *configs.Config) *TcpTransport {
	var t = NewTransport(c)
	return &TcpTransport{t, nil, nil, make(map[string]net.TCPConn), make(map[string][]byte), make(map[string]int)}
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
		tcp.clientConn = conn
	}

	return nil
}

func (tcp *TcpTransport) WaitConnection(c *configs.Config, tun *water.Interface,
	callback func(Transport, net.Conn, net.Addr, *water.Interface)) error {
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
		go callback(tcp, tcpconn, tcpconn.RemoteAddr(), tun)
	}
	err = listen.Close()
	if err != nil {
		logger.Error("listen", "error", err)
	}
	return nil
}

func (tcp *TcpTransport) Send(addr net.Addr, conn net.Conn, msg *Message) error {
	tcpconn := conn.(*net.TCPConn)

	n := len(*msg)
	buf := make([]byte, n+2)
	buf[0] = byte(n >> 8)
	buf[1] = byte(n)
	copy(buf[2:], *msg)
	configs.GetLogger().Debug("Send data (+2)", "len", n)
	l, err := tcpconn.Write(buf)
	if err != nil {
		return err
	}
	if l < n+2 {
		return errors.New("TCP sent less data: " + strconv.Itoa(l) + " != " + strconv.Itoa(n))
	}
	return nil
}

func (tcp *TcpTransport) Receive(conn net.Conn) (*Message, int, net.Addr, error) {
	logger := configs.GetLogger()
	tcpconn := conn.(*net.TCPConn)
	addrStr := tcpconn.RemoteAddr().String()
	if _, ok := tcp.buf[addrStr]; !ok {
		tcp.buf[addrStr] = make([]byte, BUFSIZE)
		tcp.len[addrStr] = 0
	}

	// Read length - first 2 bytes
	b := make([]byte, 2)
	l := 0
	var err error
	if tcp.len[addrStr] == 0 {
		l, err = tcpconn.Read(b)
		if err != nil {
			return nil, 0, nil, err
		}
		if l != 2 {
			if l == 0 {
				return nil, 0, nil, errors.New("TCP connection closed (first read)")
			} else {
				return nil, 0, nil, errors.New("TCP read less data")
			}
		}
		//logger.Debug("Read data", "len", l)
	} else {
		b = tcp.buf[addrStr][:2]
	}
	n := int(b[0])<<8 | int(b[1])
	if n > BUFSIZE {
		return nil, 0, nil, errors.New("TCP message too long")
	}

	l = 0
	if tcp.len[addrStr] < n {
		l, err = tcpconn.Read(tcp.buf[addrStr][:n])
		if err != nil {
			return nil, 0, nil, err
		}
		logger.Debug("Read data", "len", l)
		for l < n {
			l1, err := tcpconn.Read(tcp.buf[addrStr][l:n])
			if err != nil {
				return nil, 0, nil, err
			}
			if l1 == 0 {
				return nil, 0, nil, errors.New("TCP connection closed")
			}
			logger.Debug("Read data (continue)", "len", l1)
			l += l1
		}
		tcp.len[addrStr] += l
	}
	data := make([]byte, n)
	copy(data[:], tcp.buf[addrStr][:n])
	if tcp.len[addrStr] > n {
		tcp.buf[addrStr] = tcp.buf[addrStr][n : tcp.len[addrStr]-n]
		tcp.len[addrStr] -= n
		logger.Debug("Buffer moved", "len", tcp.len[addrStr])
	} else {
		tcp.len[addrStr] = 0
	}

	logger.Debug("Got data", "len", n, "from", addrStr)
	tcp.td.PutToBuf(conn.RemoteAddr(), data[:n])
	msg := Message(data)[:n]
	return &msg, l, conn.RemoteAddr(), nil
}

func (tcp *TcpTransport) GetFromBuf(addr net.Addr) []byte {
	return tcp.td.GetFromBuf(addr)
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
