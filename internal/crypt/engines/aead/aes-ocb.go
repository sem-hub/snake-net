package aead

import (
	"crypto/aes"
	"log/slog"

	"github.com/starainrt/go-crypto/ocb"

	"github.com/sem-hub/snake-net/internal/configs"
)

type AesOcbEngine struct {
	AeadEngine
	logger *slog.Logger
}

func NewAesOcbEngine(sharedSecret []byte) *AesOcbEngine {
	engine := AesOcbEngine{}
	engine.AeadEngine = *NewAeadEngine("aes-ocb", sharedSecret)
	engine.SharedSecret = sharedSecret
	engine.logger = configs.InitLogger("aes-ocb")
	return &engine
}

func (e *AesOcbEngine) GetName() string {
	return e.EngineData.Name
}

func (e *AesOcbEngine) GetType() string {
	return e.EngineData.Type
}

func (e *AesOcbEngine) Encrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Seal", "datalen", len(data))
	block, err := aes.NewCipher(e.SharedSecret)
	if err != nil {
		return nil, err
	}
	aead, err := ocb.NewOCB(block)
	if err != nil {
		return nil, err
	}
	return e.AeadEngine.Encrypt(aead, data)
}

func (e *AesOcbEngine) Decrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Open", "datalen", len(data))
	block, err := aes.NewCipher(e.SharedSecret)
	if err != nil {
		return nil, err
	}
	aead, err := ocb.NewOCB(block)
	if err != nil {
		return nil, err
	}
	return e.AeadEngine.Decrypt(aead, data)
}
