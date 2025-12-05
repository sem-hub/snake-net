package block

import (
	"crypto/cipher"
	"log/slog"

	"github.com/sem-hub/snake-net/internal/configs"
	"golang.org/x/crypto/twofish"
)

type TwofishEngine struct {
	BlockEngine
	logger *slog.Logger
}

func NewTwofishEngine(sharedSecret []byte) *TwofishEngine {
	engine := TwofishEngine{}
	engine.BlockEngine = *NewBlockEngine("twofish", sharedSecret)
	engine.SharedSecret = sharedSecret
	engine.logger = configs.InitLogger("twofish")
	return &engine
}

func (e *TwofishEngine) GetName() string {
	return e.EngineData.Name
}

func (e *TwofishEngine) GetType() string {
	return e.EngineData.Type
}

func (e *TwofishEngine) NewCipher() (cipher.Block, error) {
	return twofish.NewCipher(e.SharedSecret)
}

func (e *TwofishEngine) Encrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Encrypt", "datalen", len(data))
	return e.BlockEngine.BlockEncrypt(e.NewCipher, data)
}

func (e *TwofishEngine) Decrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Decrypt", "datalen", len(data))
	return e.BlockEngine.BlockDecrypt(e.NewCipher, data)
}
