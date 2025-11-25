package block

import (
	"crypto/aes"
	"crypto/cipher"
	"log/slog"

	"github.com/sem-hub/snake-net/internal/configs"
)

type AesCbcEngine struct {
	BlockEngine
	logger *slog.Logger
}

func NewAesCbcEngine(sharedSecret []byte) *AesCbcEngine {
	engine := AesCbcEngine{}
	engine.BlockEngine = *NewBlockEngine("aes-cbc", sharedSecret)
	engine.SharedSecret = sharedSecret
	engine.logger = configs.InitLogger("aes-cbc")
	return &engine
}

func (e *AesCbcEngine) GetName() string {
	return e.EngineData.Name
}

func (e *AesCbcEngine) GetType() string {
	return e.EngineData.Type
}

// Only 80 or 128 bits key size supported. Using 128 bits
func (e *AesCbcEngine) NewCipher(secret []byte) (cipher.Block, error) {
	return aes.NewCipher(secret)
}

func (e *AesCbcEngine) Encrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Encrypt", "datalen", len(data))
	block, err := e.NewCipher(e.SharedSecret)
	if err != nil {
		return nil, err
	}
	return e.BlockEngine.Encrypt(block, cipher.NewCBCEncrypter, data)
}

func (e *AesCbcEngine) Decrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Decrypt", "datalen", len(data))
	block, err := e.NewCipher(e.SharedSecret)
	if err != nil {
		return nil, err
	}
	return e.BlockEngine.Decrypt(block, cipher.NewCBCDecrypter, data)
}
