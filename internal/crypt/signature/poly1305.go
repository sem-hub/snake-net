package signature

import (
	"bytes"

	"github.com/aead/poly1305"
)

type SignaturePoly1305 struct {
	Signature
}

func NewSignaturePoly1305(secret []byte) *SignaturePoly1305 {
	sig := &SignaturePoly1305{
		Signature: *NewSignature(secret, "poly1305"),
	}
	return sig
}

func (s *SignaturePoly1305) GetName() string {
	return s.name
}

func (s *SignaturePoly1305) SignLen() int {
	return 16
}

func (s *SignaturePoly1305) Verify(msg []byte, sig []byte) bool {
	s.Logger.Debug("Verify", "msg len", len(msg), "siglen", len(sig))
	var key [32]byte
	copy(key[:], s.sharedSecret)
	mac := poly1305.New(key)
	mac.Write(msg)
	expectedMAC := mac.Sum(nil)
	return bytes.Equal(sig, expectedMAC)
}

func (s *SignaturePoly1305) Sign(msg []byte) []byte {
	s.Logger.Debug("Sign", "msglen", len(msg))
	var key [32]byte
	copy(key[:], s.sharedSecret)
	mac := poly1305.New(key)
	mac.Write(msg)
	return mac.Sum(nil)
}
