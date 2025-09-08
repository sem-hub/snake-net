package crypt

import (
	"bytes"
	"crypto/ed25519"
	"net"

	"github.com/sem-hub/snake-net/internal/network/transport"
)

const first_secret = "pu6apieV6chohghah2MooshepaethuCh"

//const sign_length = 64

type Secrets struct {
	clientAddr        net.Addr
	t                 transport.Transport
	conn              net.Conn
	SharedSecret      []byte
	SessionPrivateKey ed25519.PrivateKey
	SessionPublicKey  ed25519.PublicKey
}

func NewSecrets(addr net.Addr, t transport.Transport, conn net.Conn) *Secrets {
	//logger := configs.GetLogger()
	s := Secrets{}

	s.clientAddr = addr
	s.t = t
	s.conn = conn
	s.SessionPublicKey, s.SessionPrivateKey, _ =
		ed25519.GenerateKey(bytes.NewReader([]byte(first_secret)))

	return &s
}

func (s *Secrets) GetPublicKey() *ed25519.PublicKey {
	return &s.SessionPublicKey
}

func (s *Secrets) GetPrivateKey() *ed25519.PrivateKey {
	return &s.SessionPrivateKey
}

func (s *Secrets) GetSharedSecret() []byte {
	if s.SharedSecret != nil {
		return s.SharedSecret
	} else {
		return nil
	}
}

func (s *Secrets) GetClientAddr() net.Addr {
	return s.clientAddr
}

func (s *Secrets) Verify(msg []byte, sig []byte) bool {
	return ed25519.Verify(s.SessionPublicKey, msg, sig)
}

func (s *Secrets) Sign(msg *[]byte) []byte {
	return ed25519.Sign(s.SessionPrivateKey, *msg)
}

func (s *Secrets) Close() error {
	if s.t != nil {
		return s.t.Close()
	} else {
		return nil
	}
}
