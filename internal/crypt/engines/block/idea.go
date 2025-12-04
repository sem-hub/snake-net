package block

import (
	"crypto/cipher"
	"log/slog"

	"github.com/dgryski/go-idea"
	"github.com/sem-hub/snake-net/internal/configs"
)

type IdeaEngine struct {
	BlockEngine
	logger *slog.Logger
}

func NewIdeaEngine(sharedSecret []byte) *IdeaEngine {
	engine := IdeaEngine{}
	engine.BlockEngine = *NewBlockEngine("idea", sharedSecret)
	engine.SharedSecret = sharedSecret[:16]
	engine.logger = configs.InitLogger("idea")
	return &engine
}

func (e *IdeaEngine) GetName() string {
	return e.EngineData.Name
}

func (e *IdeaEngine) GetType() string {
	return e.EngineData.Type
}

// Only 80 or 128 bits key size supported. Using 128 bits
func (e *IdeaEngine) NewCipher(secret []byte) (cipher.Block, error) {
	return idea.NewCipher(secret)
}

func (e *IdeaEngine) Encrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Encrypt", "datalen", len(data))
	block, err := e.NewCipher(e.SharedSecret)
	if err != nil {
		return nil, err
	}
	return e.BlockEngine.Encrypt(block, cipher.NewCBCEncrypter, data)
}

func (e *IdeaEngine) Decrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Decrypt", "datalen", len(data))
	block, err := e.NewCipher(e.SharedSecret)
	if err != nil {
		return nil, err
	}
	return e.BlockEngine.Decrypt(block, cipher.NewCBCDecrypter, data)
}
