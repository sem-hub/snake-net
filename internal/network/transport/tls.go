//go:build tls

package transport

import (
	mtls "crypto/tls"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
)

type TlsTransport struct {
	TransportData
	mainConn *mtls.Conn
	conn     map[netip.AddrPort]*mtls.Conn
	connLock *sync.RWMutex
}

func init() {
	RegisterTransport("tls", func(args ...interface{}) (Transport, error) {
		return NewTlsTransport(), nil
	})
}

func NewTlsTransport() *TlsTransport {
	return &TlsTransport{
		TransportData: *NewTransport(),
		mainConn:      nil,
		conn:          make(map[netip.AddrPort]*mtls.Conn),
		connLock:      &sync.RWMutex{},
	}
}

func (tls *TlsTransport) GetName() string {
	return "tls"
}

func (tls *TlsTransport) GetType() string {
	return "stream"
}

func (tls *TlsTransport) IsEncrypted() bool {
	return true
}

func (tls *TlsTransport) Init(mode string, rAddrPort, lAddrPort netip.AddrPort,
	callback func(Transport, netip.AddrPort)) error {
	cert, err := getCert()
	if err != nil {
		return errors.New("cannot load TLS certificate and key files")
	}

	tlsCfg := buildTlsConfig(cert)

	if mode == "server" {
		// Do not block
		go func() {
			tls.listen(lAddrPort.String(), tlsCfg, callback)
		}()
	} else {
		family := "tcp"
		if strings.Contains(rAddrPort.String(), "[") {
			family = "tcp6"
		}
		remoteAddr, err := net.ResolveTCPAddr(family, rAddrPort.String())
		if err != nil {
			return errors.New("ResolveTCPAddr error: " + err.Error())
		}
		conn, err := mtls.Dial(family, remoteAddr.String(), tlsCfg)
		if err != nil {
			return errors.New("DialTLS error: " + err.Error())
		}
		tls.mainConn = conn
		tls.connLock.Lock()
		netipRemote := conn.RemoteAddr().(*net.TCPAddr).AddrPort()
		netipRemote = netip.AddrPortFrom(netipRemote.Addr().Unmap(), netipRemote.Port())
		tls.conn[netipRemote] = conn
		tls.connLock.Unlock()
		tls.logger.Info("Connected to server", "rAddrPort", rAddrPort, "from", conn.LocalAddr().String())
	}

	return nil
}

func (tls *TlsTransport) listen(addrPort string, cfg *mtls.Config, callback func(Transport, netip.AddrPort)) error {
	tls.logger.Info("Listen for connection", "on", addrPort)
	listen, err := mtls.Listen("tcp", addrPort, cfg)
	if err != nil {
		return err
	}

	for {
		conn, err := listen.Accept()
		if err != nil {
			tls.logger.Error("listen", "error", err)
			break
		}

		tlsconn := conn.(*mtls.Conn)
		addrPort := tlsconn.RemoteAddr().(*net.TCPAddr).AddrPort()
		// unmap this AddrPort
		addrPort = netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port())

		tls.logger.Info("New TLS connection from", "addr", addrPort.String())
		tls.connLock.Lock()
		tls.conn[addrPort] = tlsconn
		tls.connLock.Unlock()
		go callback(tls, addrPort)
	}
	err = listen.Close()
	if err != nil {
		tls.logger.Error("listen Close", "error", err)
	}
	return nil
}

func (tls *TlsTransport) Send(addr netip.AddrPort, buf *Message) error {
	tls.connLock.RLock()
	tlsconn, ok := tls.conn[addr]
	tls.connLock.RUnlock()
	if !ok {
		return errors.New("No such client connection: " + addr.String())
	}

	n := len(*buf)
	tls.logger.Debug("Send data to network", "len", n)
	l, err := tlsconn.Write(*buf)
	if err != nil {
		return err
	}
	if l < n {
		return errors.New("TLS sent less data: " + strconv.Itoa(l) + " != " + strconv.Itoa(n))
	}
	return nil
}

func (tls *TlsTransport) Receive(addr netip.AddrPort) (Message, int, error) {
	tls.connLock.RLock()
	tlsconn, ok := tls.conn[addr]
	tls.connLock.RUnlock()
	if !ok {
		return nil, 0, errors.New("No such client connection: " + addr.String())
	}

	b := make([]byte, NETBUFSIZE)
	l, err := tlsconn.Read(b)
	if err != nil {
		return nil, 0, err
	}

	tls.logger.Debug("Got data", "len", l, "from", addr.String())
	msg := Message(b)[:l]
	return msg, l, nil
}

func (tls *TlsTransport) CloseClient(addr netip.AddrPort) error {
	tls.logger.Debug("TLS CloseClient", "addr", addr.String())
	tls.connLock.RLock()
	tlsconn, ok := tls.conn[addr]
	tls.connLock.RUnlock()
	if !ok {
		return errors.New("No such client connection: " + addr.String())
	}

	err := tlsconn.Close()
	if err != nil {
		return err
	}
	tls.connLock.Lock()
	delete(tls.conn, addr)
	tls.connLock.Unlock()

	return nil
}

func (tls *TlsTransport) Close() error {
	tls.logger.Info("TLS Transport Close")
	if tls.mainConn != nil {
		err := tls.mainConn.Close()
		if err != nil {
			return err
		}
	}

	return nil
}
