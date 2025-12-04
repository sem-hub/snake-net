package signature

import (
	"crypto/ed25519"
	"log/slog"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/interfaces"
)

type SignatureEd25519 struct {
	Signature
	secret interfaces.SecretsInterface
	logger *slog.Logger
}

func NewSignatureEd25519(secret interfaces.SecretsInterface) *SignatureEd25519 {
	sig := &SignatureEd25519{
		Signature: *NewSignature(),
		secret:    secret,
	}
	sig.name = "ed25519"
	sig.logger = configs.InitLogger("signature-ed25519")
	return sig
}

func (s *SignatureEd25519) GetName() string {
	return s.name
}

func (s *SignatureEd25519) SignLen() int {
	return 64
}

func (s *SignatureEd25519) Verify(msg []byte, sig []byte) bool {
	s.logger.Debug("Verify", "msg len", len(msg), "siglen", len(sig))
	return ed25519.Verify(*s.secret.GetPublicKey(), msg, sig)
}

func (s *SignatureEd25519) Sign(msg []byte) []byte {
	s.logger.Debug("Sign", "msglen", len(msg))
	return ed25519.Sign(*s.secret.GetPrivateKey(), msg)
}
