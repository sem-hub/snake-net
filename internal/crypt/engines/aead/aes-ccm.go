package aead

import (
	"crypto/aes"
	"crypto/cipher"
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

func (e *AesCcmEngine) NewAEAD() (cipher.AEAD, error) {
	block, err := aes.NewCipher(e.SharedSecret)
	if err != nil {
		return nil, err
	}
	return ccm.NewCCM(block)
}

func (e *AesCcmEngine) Encrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Seal", "datalen", len(data))
	return e.AeadEngine.Seal(e.NewAEAD, data)
}

func (e *AesCcmEngine) Decrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Open", "datalen", len(data))
	return e.AeadEngine.Open(e.NewAEAD, data)
}
