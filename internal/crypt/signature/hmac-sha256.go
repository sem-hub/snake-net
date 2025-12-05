package signature

import (
	"crypto/hmac"
	"crypto/sha256"
	"log/slog"

	"github.com/sem-hub/snake-net/internal/configs"
)

type SignatureHMACSHA256 struct {
	Signature
	logger *slog.Logger
}

func NewSignatureHMACSHA256(secret []byte) *SignatureHMACSHA256 {
	sig := &SignatureHMACSHA256{
		Signature: *NewSignature(secret),
	}
	sig.name = "hmac-sha256"
	sig.logger = configs.InitLogger("signature-hmac-sha256")
	return sig
}

func (s *SignatureHMACSHA256) GetName() string {
	return s.name
}

func (s *SignatureHMACSHA256) SignLen() int {
	return 32
}

func (s *SignatureHMACSHA256) Verify(msg []byte, sig []byte) bool {
	s.logger.Debug("Verify", "msg len", len(msg), "siglen", len(sig))
	mac := hmac.New(sha256.New, s.sharedSecret)
	mac.Write(msg)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(sig, expectedMAC)
}

func (s *SignatureHMACSHA256) Sign(msg []byte) []byte {
	s.logger.Debug("Sign", "msglen", len(msg))
	mac := hmac.New(sha256.New, s.sharedSecret)
	mac.Write(msg)
	return mac.Sum(nil)
}
