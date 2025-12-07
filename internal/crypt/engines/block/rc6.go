package block

import (
	"crypto/cipher"
	"errors"
	"log/slog"

	rc6 "github.com/CampNowhere/golang-rc6"
	"github.com/sem-hub/snake-net/internal/configs"
)

type Rc6Engine struct {
	BlockEngine
	logger *slog.Logger
}

func NewRc6Engine(sharedSecret []byte, size int) (*Rc6Engine, error) {
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
		logger := configs.InitLogger("rc6")
		logger.Error("Invalid key size for RC6", "size", size)
		return nil, errors.New("invalid key size")
	}
	keySize := size / 8

	engine := Rc6Engine{}
	engine.BlockEngine = *NewBlockEngine("rc6", sharedSecret)
	engine.SharedSecret = sharedSecret[:keySize]
	engine.logger = configs.InitLogger("rc6")
	return &engine, nil
}

func (e *Rc6Engine) GetName() string {
	return e.EngineData.Name
}

func (e *Rc6Engine) GetType() string {
	return e.EngineData.Type
}

func (e *Rc6Engine) NewCipher() (cipher.Block, error) {
	return rc6.NewCipher(e.SharedSecret), nil
}

func (e *Rc6Engine) Encrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Encrypt", "datalen", len(data))
	return e.BlockEngine.BlockEncrypt(e.NewCipher, data)
}

func (e *Rc6Engine) Decrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Decrypt", "datalen", len(data))
	return e.BlockEngine.BlockDecrypt(e.NewCipher, data)
}
