//go:build quic

package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"

	mquic "github.com/quic-go/quic-go"
)

type QuicTransport struct {
	TransportData
	listenConn *mquic.Listener
	conn       map[netip.AddrPort]*mquic.Conn
	stream     map[netip.AddrPort]*mquic.Stream
	connLock   *sync.RWMutex
}

func init() {
	RegisterTransport("quic", func(args ...interface{}) (Transport, error) {
		return NewQuicTransport(), nil
	})
}

func NewQuicTransport() *QuicTransport {
	return &QuicTransport{
		TransportData: *NewTransport(),
		listenConn:    nil,
		conn:          make(map[netip.AddrPort]*mquic.Conn),
		stream:        make(map[netip.AddrPort]*mquic.Stream),
		connLock:      &sync.RWMutex{},
	}
}

func (quic *QuicTransport) GetName() string {
	return "quic"
}

func (quic *QuicTransport) GetType() string {
	return "stream"
}

func (quic *QuicTransport) WireProtocol() string {
	return "udp"
}

func (quic *QuicTransport) IsEncrypted() bool {
	return true
}

func (quic *QuicTransport) Init(mode string, rAddrPort, lAddrPort netip.AddrPort,
	callback func(Transport, netip.AddrPort)) error {
	cert, err := getCert()
	if err != nil {
		return errors.New("cannot load TLS certificate and key files")
	}

	tlsCfg := buildTlsConfig(cert)
	tlsCfg.MinVersion = tls.VersionTLS13
	tlsCfg.NextProtos = []string{"quic-protocol"}

	if mode == "server" {
		// Do not block
		go func() {
			quic.listen(lAddrPort.String(), tlsCfg, callback)
		}()
	} else {
		quic.logger.Info("Connect", "to", rAddrPort.String())
		conn, err := mquic.DialAddr(context.Background(), rAddrPort.String(), tlsCfg, nil)
		if err != nil {
			return errors.New("DialAddr error: " + err.Error())
		}
		stream, err := conn.OpenStreamSync(context.Background())
		if err != nil {
			quic.logger.Error("Dial error", "err", err)
			return err
		}
		quic.connLock.Lock()
		quic.conn[rAddrPort] = conn
		quic.stream[rAddrPort] = stream
		quic.connLock.Unlock()
		quic.logger.Info("Connected to", "server", rAddrPort, "from", conn.LocalAddr().String())
	}

	return nil
}

func (quic *QuicTransport) listen(addrPort string, cfg *tls.Config, callback func(Transport, netip.AddrPort)) error {
	quic.logger.Info("Listen for connection", "on", addrPort)
	var err error
	quic.listenConn, err = mquic.ListenAddr(addrPort, cfg, nil)
	if err != nil {
		quic.logger.Error("ListenAddr()", "err", err)
		return err
	}

	for {
		conn, err := quic.listenConn.Accept(context.Background())
		if err != nil {
			quic.logger.Error("Accept error:", "err", err)
			return err
		}

		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			quic.logger.Error("AcceptStream error:", "err", err)
			return err
		}
		remoteAddr := conn.RemoteAddr().(*net.UDPAddr).AddrPort()
		remoteAddr = netip.AddrPortFrom(remoteAddr.Addr().Unmap(), remoteAddr.Port())

		quic.logger.Info("New QUIC connection from", "addr", remoteAddr.String())
		quic.connLock.Lock()
		quic.conn[remoteAddr] = conn
		quic.stream[remoteAddr] = stream
		quic.connLock.Unlock()
		go callback(quic, remoteAddr)
	}
	/*err = conn.Close()
	if err != nil {
		quic.logger.Error("listen Close", "error", err)
	}*/
	//return nil
}

func (quic *QuicTransport) Send(addr netip.AddrPort, buf *Message) error {
	quic.connLock.RLock()
	quicconn, ok := quic.stream[addr]
	quic.connLock.RUnlock()
	if !ok {
		return errors.New("No such client connection: " + addr.String())
	}

	n := len(*buf)
	quic.logger.Debug("Send data to network", "len", n)
	l, err := quicconn.Write(*buf)
	if err != nil {
		return err
	}
	if l < n {
		return errors.New("QUIC sent less data: " + strconv.Itoa(l) + " != " + strconv.Itoa(n))
	}
	return nil
}

func (quic *QuicTransport) Receive(addr netip.AddrPort) (Message, int, error) {
	quic.connLock.RLock()
	qstream, ok := quic.stream[addr]
	quic.connLock.RUnlock()
	if !ok {
		return nil, 0, errors.New("No such client connection: " + addr.String())
	}

	b := make([]byte, NETBUFSIZE)
	l, err := qstream.Read(b)
	if err != nil {
		return nil, 0, err
	}

	quic.logger.Debug("Got data", "len", l, "from", addr.String())
	msg := Message(b)[:l]
	return msg, l, nil
}

func (quic *QuicTransport) CloseClient(addr netip.AddrPort) error {
	quic.logger.Debug("QUIC CloseClient", "addr", addr.String())
	quic.connLock.RLock()
	stream, ok := quic.stream[addr]
	quic.connLock.RUnlock()
	if !ok {
		return errors.New("No such client connection: " + addr.String())
	}

	err := stream.Close()
	if err != nil {
		return err
	}
	quic.connLock.Lock()
	delete(quic.conn, addr)
	delete(quic.stream, addr)
	quic.connLock.Unlock()
	return nil
}

func (quic *QuicTransport) Close() error {
	quic.logger.Info("QUIC Transport Close")
	if quic.listenConn != nil {
		quic.listenConn.Close()
	}

	return nil
}
