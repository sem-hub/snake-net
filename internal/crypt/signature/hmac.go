package signature

import (
	"crypto/hmac"
	"crypto/sha256"
	"log/slog"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/crypt"
)

type SignatureHMAC struct {
	Signature
	secret crypt.Secrets
	logger *slog.Logger
}

func NewSignatureHMAC(secret *crypt.Secrets) *SignatureHMAC {
	sig := &SignatureHMAC{
		Signature: *NewSignature(),
		secret:    *secret,
	}
	sig.logger = configs.InitLogger("signature-hmac")
	return sig
}

func (s *SignatureHMAC) SignLen() int {
	return 32
}

func (s *SignatureHMAC) Verify(msg []byte, sig []byte) bool {
	s.logger.Debug("Verify", "msg len", len(msg), "siglen", len(sig))
	mac := hmac.New(sha256.New, s.secret.GetSharedSecret())
	mac.Write(msg)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(sig, expectedMAC)
}

func (s *SignatureHMAC) Sign(msg []byte) []byte {
	s.logger.Debug("Sign", "msglen", len(msg))
	mac := hmac.New(sha256.New, s.secret.GetSharedSecret())
	mac.Write(msg)
	return mac.Sum(nil)
}
