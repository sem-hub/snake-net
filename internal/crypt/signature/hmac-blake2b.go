//go:build hmac_blake2b

package signature

import (
	"crypto/hmac"

	"golang.org/x/crypto/blake2b"
)

func init() {
	RegisterSignatureEngine("hmac-blake2b", func(sharedSecret []byte) SignatureInterface {
		return NewSignatureHMACBlake(sharedSecret)
	})
}

type SignatureHMACBlake struct {
	Signature
}

func NewSignatureHMACBlake(secret []byte) *SignatureHMACBlake {
	sig := &SignatureHMACBlake{
		Signature: *NewSignature(secret, "hmac-blake2b"),
	}
	return sig
}

func (s *SignatureHMACBlake) GetName() string {
	return s.name
}

func (s *SignatureHMACBlake) SignLen() int {
	return 64
}

func (s *SignatureHMACBlake) Verify(msg []byte, sig []byte) bool {
	s.Logger.Debug("Verify", "msg len", len(msg), "siglen", len(sig))
	hash, err := blake2b.New512(s.sharedSecret)
	if err != nil {
		s.Logger.Error("blake2b.New512", "error", err)
		return false
	}
	hash.Write(msg)
	expectedMAC := hash.Sum(nil)
	return hmac.Equal(sig, expectedMAC)
}

func (s *SignatureHMACBlake) Sign(msg []byte) []byte {
	s.Logger.Debug("Sign", "msglen", len(msg))
	hash, err := blake2b.New512(s.sharedSecret)
	if err != nil {
		s.Logger.Error("blake2b.New512", "error", err)
		return nil
	}
	hash.Write(msg)
	return hash.Sum(nil)
}
