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

	utls "github.com/refraction-networking/utls"
	"github.com/sem-hub/snake-net/internal/configs"
)

type TlsTransport struct {
	TransportData
	mainConn net.Conn
	conn     map[netip.AddrPort]net.Conn
	readBuf  map[netip.AddrPort][]byte
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
		conn:          make(map[netip.AddrPort]net.Conn),
		readBuf:       make(map[netip.AddrPort][]byte),
		connLock:      &sync.RWMutex{},
	}
}

func (tls *TlsTransport) GetName() string {
	return "tls"
}

func (tls *TlsTransport) GetType() string {
	return "stream"
}

func (tls *TlsTransport) WireProtocol() string {
	return "tcp"
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
		conn, err := tls.dialUTLS(family, rAddrPort.String(), tlsCfg)
		if err != nil {
			return errors.New("DialTLS error: " + err.Error())
		}
		tls.mainConn = conn
		tls.connLock.Lock()
		netipRemote := conn.RemoteAddr().(*net.TCPAddr).AddrPort()
		netipRemote = netip.AddrPortFrom(netipRemote.Addr().Unmap(), netipRemote.Port())
		tls.conn[netipRemote] = conn
		tls.readBuf[netipRemote] = make([]byte, NETBUFSIZE)
		tls.connLock.Unlock()
		tls.logger.Info("Connected to", "server", rAddrPort, "from", conn.LocalAddr().String())
	}

	return nil
}

func (tls *TlsTransport) dialUTLS(network, addr string, cfg *mtls.Config) (net.Conn, error) {
	rawConn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}

	utlsCerts := make([]utls.Certificate, 0, len(cfg.Certificates))
	for _, cert := range cfg.Certificates {
		sigs := make([]utls.SignatureScheme, 0, len(cert.SupportedSignatureAlgorithms))
		for _, sig := range cert.SupportedSignatureAlgorithms {
			sigs = append(sigs, utls.SignatureScheme(sig))
		}
		utlsCerts = append(utlsCerts, utls.Certificate{
			Certificate:                  cert.Certificate,
			PrivateKey:                   cert.PrivateKey,
			SupportedSignatureAlgorithms: sigs,
			OCSPStaple:                   cert.OCSPStaple,
			SignedCertificateTimestamps:  cert.SignedCertificateTimestamps,
			Leaf:                         cert.Leaf,
		})
	}

	utlsCfg := &utls.Config{
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		RootCAs:            cfg.RootCAs,
		Certificates:       utlsCerts,
		MinVersion:         cfg.MinVersion,
		MaxVersion:         cfg.MaxVersion,
		NextProtos:         cfg.NextProtos,
	}

	fingerprint := configs.GetConfig().TlsFingerprint
	clientHelloID, ok := parseUTLSClientHelloID(fingerprint)
	if !ok {
		tls.logger.Warn("Unknown uTLS fingerprint, fallback to chrome",
			"fingerprint", fingerprint,
			"fallback", "chrome")
	}

	uconn := utls.UClient(rawConn, utlsCfg, clientHelloID)
	if err := uconn.Handshake(); err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	return uconn, nil
}

func parseUTLSClientHelloID(v string) (utls.ClientHelloID, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "chrome":
		return utls.HelloChrome_Auto, true
	case "firefox":
		return utls.HelloFirefox_Auto, true
	case "ios":
		return utls.HelloIOS_Auto, true
	case "edge":
		return utls.HelloEdge_Auto, true
	case "safari":
		return utls.HelloSafari_Auto, true
	case "360":
		return utls.Hello360_Auto, true
	case "qq":
		return utls.HelloQQ_Auto, true
	case "randomized":
		return utls.HelloRandomized, true
	/*case "randomizedalpn", "randomized_alpn":
		return utls.HelloRandomizedALPN, true
	case "randomizednoalpn", "randomized_noalpn":
		return utls.HelloRandomizedNoALPN, true*/
	default:
		return utls.HelloChrome_Auto, false
	}
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

		tls.logger.Info("New TLS connection from", "addr", addrPort)
		tls.connLock.Lock()
		tls.conn[addrPort] = tlsconn
		tls.readBuf[addrPort] = make([]byte, NETBUFSIZE)
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
	b, okBuf := tls.readBuf[addr]
	tls.connLock.RUnlock()
	if !ok {
		return nil, 0, errors.New("No such client connection: " + addr.String())
	}
	if !okBuf || len(b) == 0 {
		return nil, 0, errors.New("No receive buffer for client connection: " + addr.String())
	}

	l, err := tlsconn.Read(b)
	if err != nil {
		return nil, 0, err
	}

	tls.logger.Debug("Got data", "len", l, "from", addr)
	msg := Message(b)[:l]
	return msg, l, nil
}

func (tls *TlsTransport) CloseClient(addr netip.AddrPort) error {
	tls.logger.Debug("TLS CloseClient", "addr", addr)
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
	delete(tls.readBuf, addr)
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
