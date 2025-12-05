package signature

import (
	"crypto/ed25519"
	"log/slog"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/interfaces"
)

type Signature struct {
	interfaces.SignatureInterface
	name              string
	logger            *slog.Logger
	sessionPrivateKey ed25519.PrivateKey
	sessionPublicKey  ed25519.PublicKey
	sharedSecret      []byte
}

func NewSignature(secret []byte) *Signature {
	sig := &Signature{
		sharedSecret: secret,
	}
	sig.logger = configs.InitLogger("signature")
	return sig
}

func (s *Signature) SetSharedSecret(secret []byte) {
	s.sharedSecret = secret
}

func (s *Signature) SetPublicKey(pub ed25519.PublicKey) {
	s.sessionPublicKey = pub
}

func (s *Signature) SetPrivateKey(priv ed25519.PrivateKey) {
	s.sessionPrivateKey = priv
}

func (s *Signature) GetPrivateKey() *ed25519.PrivateKey {
	return &s.sessionPrivateKey
}

func (s *Signature) GetPublicKey() *ed25519.PublicKey {
	return &s.sessionPublicKey
}
