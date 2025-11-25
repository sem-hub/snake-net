package signature

import (
	"log/slog"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/interfaces"
)

type SignatureEngine interface {
	Sign(msg []byte) []byte
	Verify(msg []byte, sig []byte) bool
	SignLen() int
}

type Signature struct {
	interfaces.SignatureInterface
	logger *slog.Logger
}

func NewSignature() *Signature {
	sig := &Signature{}
	sig.logger = configs.InitLogger("signature")
	return sig
}
