package block

import (
	"crypto/cipher"
	"errors"

	"github.com/sem-hub/snake-net/internal/configs"
	"golang.org/x/crypto/twofish"
)

type TwofishEngine struct {
	BlockEngine
	SharedSecret []byte
}

func NewTwofishEngine(sharedSecret []byte, size int) (*TwofishEngine, error) {
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
		logger := configs.InitLogger("twofish")
		logger.Error("Invalid key size for Twofish", "size", size)
		return nil, errors.New("invalid key size")
	}
	keySize := size / 8

	engine := TwofishEngine{}
	engine.BlockEngine = *NewBlockEngine("twofish")
	engine.SharedSecret = sharedSecret[:keySize]
	engine.logger = configs.InitLogger("twofish")
	return &engine, nil
}

func (e *TwofishEngine) GetName() string {
	return e.BlockEngine.Name
}

func (e *TwofishEngine) GetType() string {
	return e.BlockEngine.Type
}

func (e *TwofishEngine) NewCipher() (cipher.Block, error) {
	return twofish.NewCipher(e.SharedSecret)
}

func (e *TwofishEngine) Encrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Encrypt", "datalen", len(data))
	return e.BlockEngine.BlockEncrypt(e.NewCipher, data)
}

func (e *TwofishEngine) Decrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Decrypt", "datalen", len(data))
	return e.BlockEngine.BlockDecrypt(e.NewCipher, data)
}
