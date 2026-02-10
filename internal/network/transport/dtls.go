//go:build dtls

package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	mdtls "github.com/pion/dtls/v3"
)

type DtlsTransport struct {
	TransportData
	mainConn *mdtls.Conn
	conn     map[netip.AddrPort]*mdtls.Conn
	connLock *sync.RWMutex
}

func init() {
	RegisterTransport("dtls", func(args ...interface{}) (Transport, error) {
		return NewDtlsTransport(), nil
	})
}

func NewDtlsTransport() *DtlsTransport {
	return &DtlsTransport{
		TransportData: *NewTransport(),
		mainConn:      nil,
		conn:          make(map[netip.AddrPort]*mdtls.Conn),
		connLock:      &sync.RWMutex{},
	}
}

func (dtls *DtlsTransport) GetName() string {
	return "dtls"
}

func (dtls *DtlsTransport) GetType() string {
	return "datagram"
}

func (dtls *DtlsTransport) IsEncrypted() bool {
	return false
}

func (dtls *DtlsTransport) Init(mode string, rAddrPort, lAddrPort netip.AddrPort,
	callback func(Transport, netip.AddrPort)) error {
	cert, err := getCert()
	if err != nil {
		return errors.New("cannot load TLS certificate and key files")
	}

	dtlsConfig := &mdtls.Config{
		Certificates:         []tls.Certificate{*cert},
		InsecureSkipVerify:   true,
		ExtendedMasterSecret: mdtls.RequireExtendedMasterSecret,
	}

	family := "udp"
	if strings.Contains(rAddrPort.String(), "[") {
		family = "udp6"
	}

	if mode == "server" {
		// Do not block
		go func() {
			localAddr, err := net.ResolveUDPAddr(family, lAddrPort.String())
			if err != nil {
				dtls.logger.Error("ResolveUDPAddr local address error: " + err.Error())
				return
			}

			dtls.listen(localAddr, dtlsConfig, callback)
		}()
	} else {
		remoteAddr, err := net.ResolveUDPAddr(family, rAddrPort.String())
		if err != nil {
			return errors.New("ResolveUDPAddr remote address error: " + err.Error())
		}

		// Connect to a DTLS server
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		dtlsConn, err := mdtls.Dial(family, remoteAddr, dtlsConfig)
		if err != nil {
			return errors.New("DTLS Dial error: " + err.Error())
		}
		if err := dtlsConn.HandshakeContext(ctx); err != nil {
			return errors.New("DTLS Handshake error: " + err.Error())
		}

		addrPort := dtlsConn.RemoteAddr().(*net.UDPAddr).AddrPort()
		// unmap this AddrPort
		addrPort = netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port())

		dtls.mainConn = dtlsConn
		dtls.connLock.Lock()
		dtls.conn[addrPort] = dtlsConn
		dtls.connLock.Unlock()
		dtls.logger.Info("Connected to server", "rAddrPort", rAddrPort, "from", dtlsConn.LocalAddr().String())
	}

	return nil
}

func (dtls *DtlsTransport) listen(addrPort *net.UDPAddr, mdtlsConfig *mdtls.Config, callback func(Transport, netip.AddrPort)) error {
	dtls.logger.Info("Listen for connection", "on", addrPort)
	listen, err := mdtls.Listen("udp", addrPort, mdtlsConfig)
	if err != nil {
		return err
	}

	for {
		conn, err := listen.Accept()
		if err != nil {
			dtls.logger.Error("listen", "error", err)
			break
		}
		dtls.logger.Info("New UDP connection from", "addr", addrPort.String())

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		dtlsConn, ok := conn.(*mdtls.Conn)
		if ok {
			err = dtlsConn.HandshakeContext(ctx)
			if err != nil {
				dtls.logger.Error("DTLS Handshake error", "from", dtlsConn.RemoteAddr().String(), "error", err)
				cancel()
				continue
			}
		}
		cancel()

		addrPort := dtlsConn.RemoteAddr().(*net.UDPAddr).AddrPort()
		// unmap this AddrPort
		addrPort = netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port())

		dtls.logger.Info("Handshake completed for connection from", "addr", addrPort.String())

		dtls.connLock.Lock()
		dtls.conn[addrPort] = dtlsConn
		dtls.connLock.Unlock()
		go callback(dtls, addrPort)
	}
	err = listen.Close()
	if err != nil {
		dtls.logger.Error("listen Close", "error", err)
	}
	return nil
}

func (dtls *DtlsTransport) Send(addr netip.AddrPort, buf *Message) error {
	dtls.connLock.RLock()
	dtlsconn, ok := dtls.conn[addr]
	dtls.connLock.RUnlock()
	if !ok {
		return errors.New("No such client connection: " + addr.String())
	}

	n := len(*buf)
	dtls.logger.Debug("Send data to network", "len", n)
	l, err := dtlsconn.Write(*buf)
	if err != nil {
		return err
	}
	if l < n {
		return errors.New("TCP sent less data: " + strconv.Itoa(l) + " != " + strconv.Itoa(n))
	}
	return nil
}

func (dtls *DtlsTransport) Receive(addr netip.AddrPort) (Message, int, error) {
	dtls.connLock.RLock()
	dtlsconn, ok := dtls.conn[addr]
	dtls.connLock.RUnlock()
	if !ok {
		return nil, 0, errors.New("No such client connection: " + addr.String())
	}

	b := make([]byte, NETBUFSIZE)
	l, err := dtlsconn.Read(b)
	if err != nil {
		return nil, 0, err
	}

	dtls.logger.Debug("Got data", "len", l, "from", addr.String())
	msg := Message(b)[:l]
	return msg, l, nil
}

func (dtls *DtlsTransport) CloseClient(addr netip.AddrPort) error {
	dtls.logger.Debug("DTLS CloseClient", "addr", addr.String())
	dtls.connLock.RLock()
	dtlsconn, ok := dtls.conn[addr]
	dtls.connLock.RUnlock()
	if !ok {
		return errors.New("No such client connection: " + addr.String())
	}

	err := dtlsconn.Close()
	if err != nil {
		return err
	}
	dtls.connLock.Lock()
	delete(dtls.conn, addr)
	dtls.connLock.Unlock()
	return nil
}

func (dtls *DtlsTransport) Close() error {
	dtls.logger.Info("DTLS Transport Close")
	if dtls.mainConn != nil {
		err := dtls.mainConn.Close()
		if err != nil {
			return err
		}
	}

	return nil
}
