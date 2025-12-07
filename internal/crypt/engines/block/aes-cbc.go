package block

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"log/slog"

	"github.com/sem-hub/snake-net/internal/configs"
)

type AesCbcEngine struct {
	BlockEngine
	logger *slog.Logger
}

func NewAesCbcEngine(sharedSecret []byte, size int) (*AesCbcEngine, error) {
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
		logger := configs.InitLogger("aes-cbc")
		logger.Error("Invalid key size for AES-CBC", "size", size)
		return nil, errors.New("invalid key size")
	}
	keySize := size / 8

	engine := AesCbcEngine{}
	engine.BlockEngine = *NewBlockEngine("aes-cbc", sharedSecret)
	engine.SharedSecret = sharedSecret[:keySize]
	engine.logger = configs.InitLogger("aes-cbc")
	return &engine, nil
}

func (e *AesCbcEngine) GetName() string {
	return e.EngineData.Name
}

func (e *AesCbcEngine) GetType() string {
	return e.EngineData.Type
}

// Only 80 or 128 bits key size supported. Using 128 bits
func (e *AesCbcEngine) NewCipher() (cipher.Block, error) {
	return aes.NewCipher(e.SharedSecret)
}

func (e *AesCbcEngine) Encrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Encrypt", "datalen", len(data))
	return e.BlockEngine.BlockEncrypt(e.NewCipher, data)
}

func (e *AesCbcEngine) Decrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Decrypt", "datalen", len(data))
	return e.BlockEngine.BlockDecrypt(e.NewCipher, data)
}
