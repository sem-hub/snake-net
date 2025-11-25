package aead

import (
	"crypto/aes"
	"crypto/cipher"
	"log/slog"

	"github.com/sem-hub/snake-net/internal/configs"
)

type AesGcmEngine struct {
	AeadEngine
	logger *slog.Logger
}

func NewAesGcmEngine(sharedSecret []byte) *AesGcmEngine {
	engine := AesGcmEngine{}
	engine.AeadEngine = *NewAeadEngine("aes-gcm", sharedSecret)
	engine.SharedSecret = sharedSecret
	engine.logger = configs.InitLogger("aes-gcm")
	return &engine
}

func (e *AesGcmEngine) GetName() string {
	return e.EngineData.Name
}

func (e *AesGcmEngine) GetType() string {
	return e.EngineData.Type
}

func (e *AesGcmEngine) Encrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Seal", "datalen", len(data))
	block, err := aes.NewCipher(e.SharedSecret)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return e.AeadEngine.Encrypt(aead, data)
}

func (e *AesGcmEngine) Decrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Open", "datalen", len(data))
	block, err := aes.NewCipher(e.SharedSecret)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return e.AeadEngine.Decrypt(aead, data)
}
