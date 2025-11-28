package block

import (
	"crypto/cipher"
	"log/slog"

	rc6 "github.com/CampNowhere/golang-rc6"
	"github.com/sem-hub/snake-net/internal/configs"
)

type Rc6Engine struct {
	BlockEngine
	logger *slog.Logger
}

func NewRc6Engine(sharedSecret []byte) *Rc6Engine {
	engine := Rc6Engine{}
	engine.BlockEngine = *NewBlockEngine("rc6", sharedSecret)
	engine.SharedSecret = sharedSecret
	engine.logger = configs.InitLogger("rc6")
	return &engine
}

func (e *Rc6Engine) GetName() string {
	return e.EngineData.Name
}

func (e *Rc6Engine) GetType() string {
	return e.EngineData.Type
}

// Only 80 or 128 bits key size supported. Using 128 bits
func (e *Rc6Engine) NewCipher(secret []byte) (cipher.Block, error) {
	return rc6.NewCipher(secret[:16]), nil
}

func (e *Rc6Engine) Encrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Encrypt", "datalen", len(data))
	block, err := e.NewCipher(e.SharedSecret)
	if err != nil {
		return nil, err
	}
	return e.BlockEngine.Encrypt(block, cipher.NewCBCEncrypter, data)
}

func (e *Rc6Engine) Decrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Decrypt", "datalen", len(data))
	block, err := e.NewCipher(e.SharedSecret)
	if err != nil {
		return nil, err
	}
	return e.BlockEngine.Decrypt(block, cipher.NewCBCDecrypter, data)
}
