package block

import (
	"crypto/cipher"
	"log/slog"

	"github.com/rmuch/gost"
	"github.com/sem-hub/snake-net/internal/configs"
)

// GOST28147-89 block cipher engine
type GostEngine struct {
	BlockEngine
	logger *slog.Logger
}

func NewGostEngine(sharedSecret []byte) *GostEngine {
	engine := GostEngine{}
	engine.BlockEngine = *NewBlockEngine("gost", sharedSecret)
	engine.SharedSecret = sharedSecret
	engine.logger = configs.InitLogger("gost")
	return &engine
}

func (e *GostEngine) GetName() string {
	return e.EngineData.Name
}

func (e *GostEngine) GetType() string {
	return e.EngineData.Type
}

func (e *GostEngine) NewCipher(secret []byte) (cipher.Block, error) {
	return gost.NewBlockCipher(secret, gost.SboxIdtc26gost28147paramZ)
}

func (e *GostEngine) Encrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Encrypt", "datalen", len(data))
	block, err := e.NewCipher(e.SharedSecret)
	if err != nil {
		return nil, err
	}
	return e.BlockEngine.Encrypt(block, cipher.NewCBCEncrypter, data)
}

func (e *GostEngine) Decrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Decrypt", "datalen", len(data))
	block, err := e.NewCipher(e.SharedSecret)
	if err != nil {
		return nil, err
	}
	return e.BlockEngine.Decrypt(block, cipher.NewCBCDecrypter, data)
}
