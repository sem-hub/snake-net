package block

import (
	"crypto/cipher"
	"log/slog"

	"github.com/sem-hub/snake-net/internal/configs"
	present "github.com/yi-jiayu/PRESENT.go"
)

type PresentEngine struct {
	BlockEngine
	logger *slog.Logger
}

func NewPresentEngine(sharedSecret []byte) *PresentEngine {
	engine := PresentEngine{}
	engine.BlockEngine = *NewBlockEngine("present", sharedSecret)
	engine.SharedSecret = sharedSecret[:16]
	engine.logger = configs.InitLogger("present")
	return &engine
}

func (e *PresentEngine) GetName() string {
	return e.EngineData.Name
}

func (e *PresentEngine) GetType() string {
	return e.EngineData.Type
}

// Only 80 or 128 bits key size supported. Using 128 bits
func (e *PresentEngine) NewCipher() (cipher.Block, error) {
	return present.NewCipher(e.SharedSecret)
}

func (e *PresentEngine) Encrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Encrypt", "datalen", len(data))
	return e.BlockEngine.BlockEncrypt(e.NewCipher, data)
}

func (e *PresentEngine) Decrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Decrypt", "datalen", len(data))
	return e.BlockEngine.BlockDecrypt(e.NewCipher, data)
}
