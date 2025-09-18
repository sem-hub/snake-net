package transport

import (
	"errors"
	"log/slog"
	"net"
	"strconv"
)

const BUFSIZE = 4000

type TcpTransport struct {
	td       *TransportData
	mainConn *net.TCPConn
	conn     map[string]net.TCPConn
}

func NewTcpTransport(logger *slog.Logger) *TcpTransport {
	var t = NewTransport(logger)
	return &TcpTransport{t, nil, make(map[string]net.TCPConn)}
}

func (tcp *TcpTransport) GetName() string {
	return "tcp"
}

func (tcp *TcpTransport) Init(mode string, rAddr string, rPort string, lAddr string, lPort string,
	callback func(Transport, net.Conn, net.Addr)) error {
	if mode != "server" {
		tcpServer, err := net.ResolveTCPAddr("tcp", rAddr+":"+rPort)
		if err != nil {
			return err
		}
		conn, err := net.DialTCP("tcp", nil, tcpServer)
		if err != nil {
			return err
		}
		tcp.mainConn = conn
	} else {
		tcp.listen(rAddr, rPort, callback)
	}

	return nil
}

func (tcp *TcpTransport) listen(rAddr string, rPort string, callback func(Transport, net.Conn, net.Addr)) error {
	logger.Debug("Listen for connection")
	listen, err := net.Listen("tcp", rAddr+":"+rPort)
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
	logger.Debug("Send data to network", "len", n)
	l, err := tcpconn.Write(*buf)
	if err != nil {
		return err
	}
	if l < n {
		return errors.New("TCP sent less data: " + strconv.Itoa(l) + " != " + strconv.Itoa(n))
	}
	return nil
}

func (tcp *TcpTransport) Receive(conn net.Conn, addr net.Addr) (Message, int, net.Addr, error) {
	tcpconn := conn.(*net.TCPConn)
	addrStr := tcpconn.RemoteAddr().String()

	b := make([]byte, BUFSIZE)
	l, err := tcpconn.Read(b)
	if err != nil {
		return nil, 0, nil, err
	}

	logger.Debug("Got data", "len", l, "from", addrStr)
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
