package transport

import (
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
)

type TcpTransport struct {
	TransportData
	mainConn *net.TCPConn
	conn     sync.Map // [netip.AddrPort]net.TCPConn
}

func NewTcpTransport(logger *slog.Logger) *TcpTransport {
	return &TcpTransport{TransportData: *NewTransport(logger), mainConn: nil, conn: sync.Map{}}
}

func (tcp *TcpTransport) GetName() string {
	return "tcp"
}

func (tcp *TcpTransport) GetType() string {
	return "stream"
}

func (tcp *TcpTransport) IsEncrypted() bool {
	return false
}

func (tcp *TcpTransport) Init(mode string, rAddr string, rPort string, lAddr string, lPort string,
	callback func(Transport, netip.AddrPort)) error {
	if mode == "server" {
		tcp.listen(lAddr, lPort, callback)
	} else {
		family := "tcp"
		if strings.Contains(rAddr, ":") {
			family = "tcp6"
		}
		tcpServer, err := net.ResolveTCPAddr(family, rAddr+":"+rPort)
		if err != nil {
			return errors.New("ResolveTCPAddr error: " + err.Error())
		}
		conn, err := net.DialTCP(family, nil, tcpServer)
		if err != nil {
			return errors.New("DialTCP error: " + err.Error())
		}
		tcp.mainConn = conn
		tcp.conn.Store(conn.RemoteAddr().(*net.TCPAddr).AddrPort(), conn)
		logAddr := conn.LocalAddr().String()
		logger.Info("Connected to server", "addr", rAddr, "port", rPort, "from", logAddr)
	}

	return nil
}

func (tcp *TcpTransport) listen(addr string, port string, callback func(Transport, netip.AddrPort)) error {
	logger.Debug("Listen for connection", "on", addr+":"+port)
	listen, err := net.Listen("tcp", addr+":"+port)
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
		addrPort := tcpconn.RemoteAddr().(*net.TCPAddr).AddrPort()
		addrPort = netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port())

		logger.Debug("New TCP connection from", "addr", addrPort.String())
		tcp.conn.Store(addrPort, tcpconn)
		go callback(tcp, addrPort)
	}
	err = listen.Close()
	if err != nil {
		logger.Error("listen", "error", err)
	}
	return nil
}

func (tcp *TcpTransport) Send(addr netip.AddrPort, buf *Message) error {
	val, ok := tcp.conn.Load(addr)
	if !ok {
		return errors.New("No such client connection: " + addr.String())
	}
	tcpconn := val.(*net.TCPConn)

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

func (tcp *TcpTransport) Receive(addr netip.AddrPort) (Message, int, error) {
	val, ok := tcp.conn.Load(addr)
	if !ok {
		return nil, 0, errors.New("No such client connection: " + addr.String())
	}
	tcpconn := val.(*net.TCPConn)

	b := make([]byte, NETBUFSIZE)
	l, err := tcpconn.Read(b)
	if err != nil {
		return nil, 0, err
	}

	logger.Debug("Got data", "len", l, "from", addr.String())
	msg := Message(b)[:l]
	return msg, l, nil
}

func (tcp *TcpTransport) CloseClient(addr netip.AddrPort) error {
	val, ok := tcp.conn.Load(addr)
	if !ok {
		return errors.New("No such client connection: " + addr.String())
	}
	tcpconn := val.(*net.TCPConn)

	err := tcpconn.Close()
	if err != nil {
		return err
	}
	tcp.conn.Delete(addr)
	return nil
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
