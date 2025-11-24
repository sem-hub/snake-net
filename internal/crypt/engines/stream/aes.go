package stream

import (
	"crypto/aes"
	"crypto/cipher"
	"log/slog"

	"github.com/sem-hub/snake-net/internal/configs"
)

type AesEngine struct {
	StreamEngine
	logger *slog.Logger
}

func NewAesEngine(sharedSecret []byte) *AesEngine {
	engine := AesEngine{}
	engine.StreamEngine = *NewStreamEngine(sharedSecret)
	engine.SharedSecret = sharedSecret
	engine.logger = configs.InitLogger("aes")
	return &engine
}

func (e *AesEngine) GetName() string {
	return e.EngineData.Name
}

func (e *AesEngine) GetType() string {
	return e.EngineData.Type
}

func (e *AesEngine) NewCipher(secret []byte) (cipher.Block, error) {
	return aes.NewCipher(secret)
}

func (e *AesEngine) Encrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Encrypt", "datalen", len(data))
	block, err := e.NewCipher(e.SharedSecret)
	if err != nil {
		return nil, err
	}
	return e.StreamEngine.Encrypt(block, cipher.NewCTR, data)
}

func (e *AesEngine) Decrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Decrypt", "datalen", len(data))
	block, err := e.NewCipher(e.SharedSecret)
	if err != nil {
		return nil, err
	}
	return e.StreamEngine.Decrypt(block, cipher.NewCTR, data)
}
