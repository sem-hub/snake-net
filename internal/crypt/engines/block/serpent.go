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

func (e *SerpentEngine) NewCipher(secret []byte) (cipher.Block, error) {
	return serpent.NewCipher(secret)
}

func (e *SerpentEngine) Encrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Encrypt", "datalen", len(data))
	block, err := e.NewCipher(e.SharedSecret)
	if err != nil {
		return nil, err
	}
	return e.BlockEngine.Encrypt(block, cipher.NewCBCEncrypter, data)
}

func (e *SerpentEngine) Decrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Decrypt", "datalen", len(data))
	block, err := e.NewCipher(e.SharedSecret)
	if err != nil {
		return nil, err
	}
	return e.BlockEngine.Decrypt(block, cipher.NewCBCDecrypter, data)
}
