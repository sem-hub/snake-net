package block

import (
	"crypto/cipher"
	"log/slog"

	"github.com/aead/camellia"
	"github.com/sem-hub/snake-net/internal/configs"
)

type CamelliaEngine struct {
	BlockEngine
	logger *slog.Logger
}

func NewCamelliaEngine(sharedSecret []byte) *CamelliaEngine {
	engine := CamelliaEngine{}
	engine.BlockEngine = *NewBlockEngine("camellia", sharedSecret)
	engine.SharedSecret = sharedSecret[:16]
	engine.logger = configs.InitLogger("camellia")
	return &engine
}

func (e *CamelliaEngine) GetName() string {
	return e.EngineData.Name
}

func (e *CamelliaEngine) GetType() string {
	return e.EngineData.Type
}

func (e *CamelliaEngine) NewCipher(secret []byte) (cipher.Block, error) {
	return camellia.NewCipher(secret)
}

func (e *CamelliaEngine) Encrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Encrypt", "datalen", len(data))
	block, err := e.NewCipher(e.SharedSecret)
	if err != nil {
		return nil, err
	}
	return e.BlockEngine.Encrypt(block, cipher.NewCBCEncrypter, data)
}

func (e *CamelliaEngine) Decrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Decrypt", "datalen", len(data))
	block, err := e.NewCipher(e.SharedSecret)
	if err != nil {
		return nil, err
	}
	return e.BlockEngine.Decrypt(block, cipher.NewCBCDecrypter, data)
}
