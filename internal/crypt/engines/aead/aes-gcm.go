package aead

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"log/slog"

	"github.com/sem-hub/snake-net/internal/configs"
)

type AesGcmEngine struct {
	AeadEngine
	logger *slog.Logger
}

func NewAesGcmEngine(sharedSecret []byte, size int) (*AesGcmEngine, error) {
	allowedKeySizes := []int{128, 192, 256}
	if size == 0 {
		size = 256
	}

	found := false
	for _, s := range allowedKeySizes {
		if size == s {
			found = true
			break
		}
	}

	if !found {
		logger := configs.InitLogger("aes-gcm")
		logger.Error("Invalid key size for AES-GCM", "size", size)
		return nil, errors.New("invalid key size")
	}

	keySize := size / 8

	engine := AesGcmEngine{}
	engine.AeadEngine = *NewAeadEngine("aes-gcm")
	engine.SharedSecret = sharedSecret[:keySize]
	engine.logger = configs.InitLogger("aes-gcm")
	return &engine, nil
}

func (e *AesGcmEngine) GetName() string {
	return e.EngineData.Name
}

func (e *AesGcmEngine) GetType() string {
	return e.EngineData.Type
}

func (e *AesGcmEngine) NewAEAD() (cipher.AEAD, error) {
	block, err := aes.NewCipher(e.SharedSecret)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (e *AesGcmEngine) Encrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Seal", "datalen", len(data))
	return e.AeadEngine.Seal(e.NewAEAD, data)
}

func (e *AesGcmEngine) Decrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Open", "datalen", len(data))
	return e.AeadEngine.Open(e.NewAEAD, data)
}
