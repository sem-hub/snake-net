package aead

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"log/slog"

	ccm "gitlab.com/go-extension/aes-ccm"

	"github.com/sem-hub/snake-net/internal/configs"
)

type AesCcmEngine struct {
	AeadEngine
	logger *slog.Logger
}

func NewAesCcmEngine(sharedSecret []byte, size int) (*AesCcmEngine, error) {
	if size == 0 {
		size = 256
	}
	allowedKeySizes := []int{128, 192, 256}

	found := false
	for _, s := range allowedKeySizes {
		if size == s {
			found = true
			break
		}
	}

	if !found {
		logger := configs.InitLogger("aes-ccm")
		logger.Error("Invalid key size for AES-CCM", "size", size)
		return nil, errors.New("invalid key size")
	}

	keySize := size / 8
	engine := AesCcmEngine{}
	engine.AeadEngine = *NewAeadEngine("aes-ccm")
	engine.SharedSecret = sharedSecret[:keySize]
	engine.logger = configs.InitLogger("aes-ccm")
	return &engine, nil
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
