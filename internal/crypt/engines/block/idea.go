package block

import (
	"crypto/cipher"
	"log/slog"

	"github.com/dgryski/go-idea"
	"github.com/sem-hub/snake-net/internal/configs"
)

type IdeaEngine struct {
	BlockEngine
	SharedSecret []byte
	logger       *slog.Logger
}

// Only 128 bits key size
func NewIdeaEngine(sharedSecret []byte) (*IdeaEngine, error) {
	engine := IdeaEngine{}
	engine.BlockEngine = *NewBlockEngine("idea")
	engine.SharedSecret = sharedSecret[:16]
	engine.logger = configs.InitLogger("idea")
	return &engine, nil
}

func (e *IdeaEngine) GetName() string {
	return e.BlockEngine.Name
}

func (e *IdeaEngine) GetType() string {
	return e.BlockEngine.Type
}

func (e *IdeaEngine) NewCipher() (cipher.Block, error) {
	return idea.NewCipher(e.SharedSecret)
}

func (e *IdeaEngine) Encrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Encrypt", "datalen", len(data))
	return e.BlockEngine.BlockEncrypt(e.NewCipher, data)
}

func (e *IdeaEngine) Decrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Decrypt", "datalen", len(data))
	return e.BlockEngine.BlockDecrypt(e.NewCipher, data)
}
