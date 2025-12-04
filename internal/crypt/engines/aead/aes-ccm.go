package aead

import (
	"crypto/aes"
	"log/slog"

	ccm "gitlab.com/go-extension/aes-ccm"

	"github.com/sem-hub/snake-net/internal/configs"
)

type AesCcmEngine struct {
	AeadEngine
	logger *slog.Logger
}

func NewAesCcmEngine(sharedSecret []byte) *AesCcmEngine {
	engine := AesCcmEngine{}
	engine.AeadEngine = *NewAeadEngine("aes-ccm", sharedSecret)
	engine.SharedSecret = sharedSecret
	engine.logger = configs.InitLogger("aes-ccm")
	return &engine
}

func (e *AesCcmEngine) GetName() string {
	return e.EngineData.Name
}

func (e *AesCcmEngine) GetType() string {
	return e.EngineData.Type
}

func (e *AesCcmEngine) Encrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Seal", "datalen", len(data))
	block, err := aes.NewCipher(e.SharedSecret)
	if err != nil {
		return nil, err
	}
	aead, err := ccm.NewCCM(block)
	if err != nil {
		return nil, err
	}
	return e.AeadEngine.Encrypt(aead, data)
}

func (e *AesCcmEngine) Decrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Open", "datalen", len(data))
	block, err := aes.NewCipher(e.SharedSecret)
	if err != nil {
		return nil, err
	}
	aead, err := ccm.NewCCM(block)
	if err != nil {
		return nil, err
	}
	return e.AeadEngine.Decrypt(aead, data)
}
