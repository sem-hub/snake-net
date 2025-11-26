package signature

import (
	"log/slog"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/interfaces"
)

type Signature struct {
	interfaces.SignatureInterface
	logger *slog.Logger
}

func NewSignature() *Signature {
	sig := &Signature{}
	sig.logger = configs.InitLogger("signature")
	return sig
}
