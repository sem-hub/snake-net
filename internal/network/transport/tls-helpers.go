//go:build tls || dtls || quic

package transport

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	mtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	"github.com/sem-hub/snake-net/internal/configs"
)

func getCert() (*mtls.Certificate, error) {
	cfg := configs.GetConfig()
	cert_file := cfg.CertFile
	key_file := cfg.KeyFile

	// Load certificate from files
	if cert_file != "" && key_file != "" {
		cert, err := mtls.LoadX509KeyPair(cert_file, key_file)
		if err != nil {
			return nil, err
		}
		return &cert, nil
	}

	// Generate self-signed certificate
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
