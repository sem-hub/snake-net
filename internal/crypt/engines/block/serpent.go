package block

import (
	"crypto/cipher"
	"log/slog"

	"github.com/aead/serpent"
	"github.com/sem-hub/snake-net/internal/configs"
)

type SerpentEngine struct {
	BlockEngine
	logger *slog.Logger
}

func NewSerpentEngine(sharedSecret []byte) *SerpentEngine {
	engine := SerpentEngine{}
	engine.BlockEngine = *NewBlockEngine("serpent", sharedSecret)
	engine.SharedSecret = sharedSecret[:16]
	engine.logger = configs.InitLogger("serpent")
	return &engine
}

func (e *SerpentEngine) GetName() string {
	return e.EngineData.Name
}

func (e *SerpentEngine) GetType() string {
	return e.EngineData.Type
}

func (e *SerpentEngine) NewCipher() (cipher.Block, error) {
	return serpent.NewCipher(e.SharedSecret)
}

func (e *SerpentEngine) Encrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Encrypt", "datalen", len(data))
	return e.BlockEngine.BlockEncrypt(e.NewCipher, data)
}

func (e *SerpentEngine) Decrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Decrypt", "datalen", len(data))
	return e.BlockEngine.BlockDecrypt(e.NewCipher, data)
}
