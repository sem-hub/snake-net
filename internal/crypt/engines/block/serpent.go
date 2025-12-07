package block

import (
	"crypto/cipher"
	"errors"

	"github.com/aead/serpent"
	"github.com/sem-hub/snake-net/internal/configs"
)

type SerpentEngine struct {
	BlockEngine
	SharedSecret []byte
}

func NewSerpentEngine(sharedSecret []byte, size int) (*SerpentEngine, error) {
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
		logger := configs.InitLogger("serpent")
		logger.Error("Invalid key size for SERPENT", "size", size)
		return nil, errors.New("invalid key size")
	}
	keySize := size / 8

	engine := SerpentEngine{}
	engine.BlockEngine = *NewBlockEngine("serpent")
	engine.SharedSecret = sharedSecret[:keySize]
	engine.logger = configs.InitLogger("serpent")
	return &engine, nil
}

func (e *SerpentEngine) GetName() string {
	return e.BlockEngine.Name
}

func (e *SerpentEngine) GetType() string {
	return e.BlockEngine.Type
}

func (e *SerpentEngine) NewCipher() (cipher.Block, error) {
	return serpent.NewCipher(e.SharedSecret)
}

func (e *SerpentEngine) Encrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Encrypt", "datalen", len(data))
	return e.BlockEngine.BlockEncrypt(e.NewCipher, data)
}

func (e *SerpentEngine) Decrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Decrypt", "datalen", len(data))
	return e.BlockEngine.BlockDecrypt(e.NewCipher, data)
}
