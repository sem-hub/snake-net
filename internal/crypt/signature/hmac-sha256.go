//go:build hmac_sha256

package signature

import (
	"crypto/hmac"
	"crypto/sha256"
)

func init() {
	RegisterSignatureEngine("hmac-sha256", func(sharedSecret []byte) SignatureInterface {
		return NewSignatureHMACSHA256(sharedSecret)
	})
}

type SignatureHMACSHA256 struct {
	Signature
}

func NewSignatureHMACSHA256(secret []byte) *SignatureHMACSHA256 {
	sig := &SignatureHMACSHA256{
		Signature: *NewSignature(secret, "hmac-sha256"),
	}
	return sig
}

func (s *SignatureHMACSHA256) GetName() string {
	return s.name
}

func (s *SignatureHMACSHA256) SignLen() int {
	return 32
}

func (s *SignatureHMACSHA256) Verify(msg []byte, sig []byte) bool {
	s.Logger.Debug("Verify", "msg len", len(msg), "siglen", len(sig))
	mac := hmac.New(sha256.New, s.sharedSecret)
	mac.Write(msg)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(sig, expectedMAC)
}

func (s *SignatureHMACSHA256) Sign(msg []byte) []byte {
	s.Logger.Debug("Sign", "msglen", len(msg))
	mac := hmac.New(sha256.New, s.sharedSecret)
	mac.Write(msg)
	return mac.Sum(nil)
}
