package stream

import (
	"crypto/aes"
	"crypto/cipher"
	"log/slog"

	"github.com/sem-hub/snake-net/internal/configs"
)

type AesCtrEngine struct {
	StreamEngine
	logger *slog.Logger
}

func NewAesCtrEngine(sharedSecret []byte) *AesCtrEngine {
	engine := AesCtrEngine{}
	engine.StreamEngine = *NewStreamEngine("aes-ctr", sharedSecret)
	engine.SharedSecret = sharedSecret
	engine.logger = configs.InitLogger("aes-ctr")
	return &engine
}

func (e *AesCtrEngine) GetName() string {
	return e.EngineData.Name
}

func (e *AesCtrEngine) GetType() string {
	return e.EngineData.Type
}

func (e *AesCtrEngine) NewCipher(secret []byte) (cipher.Block, error) {
	return aes.NewCipher(secret)
}

func (e *AesCtrEngine) Encrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Encrypt", "datalen", len(data))
	block, err := e.NewCipher(e.SharedSecret)
	if err != nil {
		return nil, err
	}
	return e.StreamEngine.Encrypt(block, cipher.NewCTR, data)
}

func (e *AesCtrEngine) Decrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Decrypt", "datalen", len(data))
	block, err := e.NewCipher(e.SharedSecret)
	if err != nil {
		return nil, err
	}
	return e.StreamEngine.Decrypt(block, cipher.NewCTR, data)
}
