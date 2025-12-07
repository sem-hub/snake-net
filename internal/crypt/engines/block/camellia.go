package block

import (
	"crypto/cipher"
	"errors"
	"log/slog"

	"github.com/aead/camellia"
	"github.com/sem-hub/snake-net/internal/configs"
)

type CamelliaEngine struct {
	BlockEngine
	SharedSecret []byte
	logger       *slog.Logger
}

func NewCamelliaEngine(sharedSecret []byte, size int) (*CamelliaEngine, error) {
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
		logger := configs.InitLogger("camellia")
		logger.Error("Invalid key size for CAMELLIA", "size", size)
		return nil, errors.New("invalid key size")
	}
	keySize := size / 8

	engine := CamelliaEngine{}
	engine.BlockEngine = *NewBlockEngine("camellia")
	engine.SharedSecret = sharedSecret[:keySize]
	engine.logger = configs.InitLogger("camellia")
	return &engine, nil
}

func (e *CamelliaEngine) GetName() string {
	return e.BlockEngine.Name
}

func (e *CamelliaEngine) GetType() string {
	return e.BlockEngine.Type
}

func (e *CamelliaEngine) NewCipher() (cipher.Block, error) {
	return camellia.NewCipher(e.SharedSecret)
}

func (e *CamelliaEngine) Encrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Encrypt", "datalen", len(data))
	return e.BlockEngine.BlockEncrypt(e.NewCipher, data)
}

func (e *CamelliaEngine) Decrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Decrypt", "datalen", len(data))
	return e.BlockEngine.BlockDecrypt(e.NewCipher, data)
}
