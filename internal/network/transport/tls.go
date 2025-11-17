package transport

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	mtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

type TlsTransport struct {
	TransportData
	mainConn *mtls.Conn
	conn     map[netip.AddrPort]*mtls.Conn
	connLock *sync.RWMutex
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

func getCert() (*mtls.Certificate, error) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, &certPrivKey.PublicKey, certPrivKey)
	if err != nil {
		return nil, err
	}
	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	certFinal, err := mtls.X509KeyPair(certPEM.Bytes(), certPrivKeyPEM.Bytes())
	if err != nil {
		return nil, err
	}
	return &certFinal, nil
}

func buildTlsConfig(cert *mtls.Certificate) *mtls.Config {
	cfg := &mtls.Config{
		Certificates:       []mtls.Certificate{*cert},
		InsecureSkipVerify: true,
	}
	return cfg
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
		tls.conn[conn.RemoteAddr().(*net.TCPAddr).AddrPort()] = conn
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
