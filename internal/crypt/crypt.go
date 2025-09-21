package crypt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
)

const FIRSTSECRET = "pu6apieV6chohghah2MooshepaethuCh"

const SIGNLEN = 64

const XORKEYLEN = 32

type Secrets struct {
	SharedSecret      []byte
	SessionPrivateKey ed25519.PrivateKey
	SessionPublicKey  ed25519.PublicKey
	XORKey            []byte
}

func NewSecrets() *Secrets {
	s := Secrets{}

	s.SessionPublicKey, s.SessionPrivateKey, _ =
		ed25519.GenerateKey(bytes.NewReader([]byte(FIRSTSECRET)))

	s.XORKey = make([]byte, XORKEYLEN)
	rand.Read(s.XORKey)

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

func (s *Secrets) Verify(msg []byte, sig []byte) bool {
	return ed25519.Verify(s.SessionPublicKey, msg, sig)
}

func (s *Secrets) Sign(msg []byte) []byte {
	return ed25519.Sign(s.SessionPrivateKey, msg)
}

func (s *Secrets) XOR(data *[]byte) {
	for i := 0; i < len(*data); i++ {
		(*data)[i] ^= s.XORKey[i%len(s.XORKey)]
	}
}
