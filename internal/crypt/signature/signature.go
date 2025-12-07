package signature

import (
	"crypto/ed25519"
	"log/slog"
	"slices"

	"github.com/sem-hub/snake-net/internal/configs"
)

var SignatureList = []string{
	"hmac-sha256",
	"hmac-blake2b",
	"ed25519",
}

type SignatureInterface interface {
	GetName() string
	SignLen() int
	Verify(msg []byte, sig []byte) bool
	Sign(msg []byte) []byte
	SetSharedSecret(secret []byte)
	SetPublicKey(pub ed25519.PublicKey)
	SetPrivateKey(priv ed25519.PrivateKey)
	GetPrivateKey() *ed25519.PrivateKey
	GetPublicKey() *ed25519.PublicKey
}

type Signature struct {
	SignatureInterface
	name              string
	Logger            *slog.Logger
	sessionPrivateKey ed25519.PrivateKey
	sessionPublicKey  ed25519.PublicKey
	sharedSecret      []byte
}

func NewSignature(secret []byte, name string) *Signature {
	sig := &Signature{
		sharedSecret: secret,
		name:         name,
	}

	sig.Logger = configs.InitLogger("signature-" + sig.name)
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

func IsEngineSupported(engine string) bool {
	return slices.Contains(SignatureList, engine)
}
