package signature

import (
	"crypto/ed25519"
)

func init() {
	RegisterSignatureEngine("ed25519", func(sharedSecret []byte) SignatureInterface {
		return NewSignatureEd25519(sharedSecret)
	})
}

type SignatureEd25519 struct {
	Signature
}

func NewSignatureEd25519(secret []byte) *SignatureEd25519 {
	sig := &SignatureEd25519{
		Signature: *NewSignature(secret, "ed25519"),
	}
	return sig
}

func (s *SignatureEd25519) GetName() string {
	return s.name
}

func (s *SignatureEd25519) SignLen() uint16 {
	return 64
}

func (s *SignatureEd25519) Verify(msg []byte, sig []byte) bool {
	s.Logger.Debug("Verify", "msg len", len(msg), "siglen", len(sig))
	return ed25519.Verify(*s.GetPublicKey(), msg, sig)
}

func (s *SignatureEd25519) Sign(msg []byte) []byte {
	s.Logger.Debug("Sign", "msglen", len(msg))
	return ed25519.Sign(*s.GetPrivateKey(), msg)
}
