package aead

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"log/slog"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/starainrt/go-crypto/ocb"
)

type AesOcbEngine struct {
	AeadEngine
	logger *slog.Logger
}

func NewAesOcbEngine(sharedSecret []byte, size int) (*AesOcbEngine, error) {
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
		logger := configs.InitLogger("aes-ocb")
		logger.Error("Invalid key size for AES-OCB", "size", size)
		return nil, errors.New("invalid key size")
	}

	keySize := size / 8
	engine := AesOcbEngine{}
	engine.AeadEngine = *NewAeadEngine("aes-ocb")
	engine.SharedSecret = sharedSecret[:keySize]
	engine.logger = configs.InitLogger("aes-ocb")
	return &engine, nil
}

func (e *AesOcbEngine) GetName() string {
	return e.EngineData.Name
}

func (e *AesOcbEngine) GetType() string {
	return e.EngineData.Type
}

func (e *AesOcbEngine) NewAEAD() (cipher.AEAD, error) {
	block, err := aes.NewCipher(e.SharedSecret)
	if err != nil {
		return nil, err
	}
	return ocb.NewOCB(block)
}

func (e *AesOcbEngine) Encrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Seal", "datalen", len(data))
	return e.AeadEngine.Seal(e.NewAEAD, data)
}

func (e *AesOcbEngine) Decrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Open", "datalen", len(data))
	return e.AeadEngine.Open(e.NewAEAD, data)
}
