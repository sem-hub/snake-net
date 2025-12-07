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

// Only 256 bits key size
func NewGostEngine(sharedSecret []byte) (*GostEngine, error) {
	engine := GostEngine{}
	engine.BlockEngine = *NewBlockEngine("gost", sharedSecret)
	engine.SharedSecret = sharedSecret
	engine.logger = configs.InitLogger("gost")
	return &engine, nil
}

func (e *GostEngine) GetName() string {
	return e.EngineData.Name
}

func (e *GostEngine) GetType() string {
	return e.EngineData.Type
}

func (e *GostEngine) NewCipher() (cipher.Block, error) {
	return gost.NewBlockCipher(e.SharedSecret, gost.SboxIdtc26gost28147paramZ)
}

func (e *GostEngine) Encrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Encrypt", "datalen", len(data))
	return e.BlockEngine.BlockEncrypt(e.NewCipher, data)
}

func (e *GostEngine) Decrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Decrypt", "datalen", len(data))
	return e.BlockEngine.BlockDecrypt(e.NewCipher, data)
}
