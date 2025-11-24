package transport

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
)

type TcpTransport struct {
	TransportData
	mainConn *net.TCPConn
	conn     map[netip.AddrPort]*net.TCPConn
	connLock *sync.RWMutex
}

func NewTcpTransport() *TcpTransport {
	return &TcpTransport{
		TransportData: *NewTransport(),
		mainConn:      nil,
		conn:          make(map[netip.AddrPort]*net.TCPConn),
		connLock:      &sync.RWMutex{},
	}
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

func (tcp *TcpTransport) Init(mode string, rAddrPort, lAddrPort netip.AddrPort,
	callback func(Transport, netip.AddrPort)) error {
	if mode == "server" {
		// Do not block
		go func() {
			tcp.listen(lAddrPort.String(), callback)
		}()
	} else {
		family := "tcp"
		if rAddrPort.Addr().Is6() {
			family = "tcp6"
		}
		remoteAddr, err := net.ResolveTCPAddr(family, rAddrPort.String())
		if err != nil {
			return errors.New("ResolveTCPAddr remote address error: " + err.Error())
		}
		localAddr, err := net.ResolveTCPAddr(family, lAddrPort.String())
		if err != nil {
			return errors.New("ResolveTCPAddr local address error: " + err.Error())
		}

		conn, err := net.DialTCP(family, localAddr, remoteAddr)
		if err != nil {
			return errors.New("DialTCP error: " + err.Error())
		}
		tcp.mainConn = conn
		tcp.connLock.Lock()
		netipRemote := conn.RemoteAddr().(*net.TCPAddr).AddrPort()
		netipRemote = netip.AddrPortFrom(netipRemote.Addr().Unmap(), netipRemote.Port())
		tcp.logger.Debug("TCP connected", "netipRemote", netipRemote.String())
		tcp.conn[netipRemote] = conn
		tcp.connLock.Unlock()
		tcp.logger.Info("Connected to server", "rAddrPort", rAddrPort, "from", conn.LocalAddr().String())
	}

	return nil
}

func (tcp *TcpTransport) listen(addrPort string, callback func(Transport, netip.AddrPort)) error {
	tcp.logger.Info("Listen for connection", "on", addrPort)
	listen, err := net.Listen("tcp", addrPort)
	if err != nil {
		return err
	}

	for {
		conn, err := listen.Accept()
		if err != nil {
			tcp.logger.Error("listen", "error", err)
			break
		}

		tcpconn := conn.(*net.TCPConn)
		tcpconn.SetNoDelay(true)
		tcpconn.SetLinger(0)
		addrPort := tcpconn.RemoteAddr().(*net.TCPAddr).AddrPort()
		// unmap this AddrPort
		addrPort = netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port())

		tcp.logger.Info("New TCP connection from", "addr", addrPort.String())
		tcp.connLock.Lock()
		tcp.conn[addrPort] = tcpconn
		tcp.connLock.Unlock()
		go callback(tcp, addrPort)
	}
	err = listen.Close()
	if err != nil {
		tcp.logger.Error("listen Close", "error", err)
	}
	return nil
}

func (tcp *TcpTransport) Send(addr netip.AddrPort, buf *Message) error {
	tcp.connLock.RLock()
	tcpconn, ok := tcp.conn[addr]
	tcp.connLock.RUnlock()
	if !ok {
		return errors.New("No such client connection: " + addr.String())
	}

	n := len(*buf)
	tcp.logger.Debug("Send data to network", "len", n)
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
	tcp.connLock.RLock()
	tcpconn, ok := tcp.conn[addr]
	tcp.connLock.RUnlock()
	if !ok {
		return nil, 0, errors.New("No such client connection: " + addr.String())
	}

	b := make([]byte, NETBUFSIZE)
	l, err := tcpconn.Read(b)
	if err != nil {
		return nil, 0, err
	}

	tcp.logger.Debug("Got data", "len", l, "from", addr.String())
	msg := Message(b)[:l]
	return msg, l, nil
}

func (tcp *TcpTransport) CloseClient(addr netip.AddrPort) error {
	tcp.logger.Debug("TCP CloseClient", "addr", addr.String())
	tcp.connLock.RLock()
	tcpconn, ok := tcp.conn[addr]
	tcp.connLock.RUnlock()
	if !ok {
		return errors.New("No such client connection: " + addr.String())
	}

	err := tcpconn.Close()
	if err != nil {
		return err
	}
	tcp.connLock.Lock()
	delete(tcp.conn, addr)
	tcp.connLock.Unlock()
	return nil
}

func (tcp *TcpTransport) Close() error {
	tcp.logger.Info("TCP Transport Close")
	if tcp.mainConn != nil {
		err := tcp.mainConn.Close()
		if err != nil {
			return err
		}
	}

	return nil
}
