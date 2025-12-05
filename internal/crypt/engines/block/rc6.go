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
	engine.SharedSecret = sharedSecret[:16]
	engine.logger = configs.InitLogger("rc6")
	return &engine
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
