package block

import (
	"crypto/cipher"
	"errors"
	"log/slog"

	"github.com/sem-hub/snake-net/internal/configs"
	present "github.com/yi-jiayu/PRESENT.go"
)

type PresentEngine struct {
	BlockEngine
	logger *slog.Logger
}

// Only 80 or 128 bits key size supported. Using 128 bits
func NewPresentEngine(sharedSecret []byte, size int) (*PresentEngine, error) {
	if size == 0 {
		size = 128
	}
	if size != 80 && size != 128 {
		logger := configs.InitLogger("present")
		logger.Error("Invalid key size for PRESENT", "size", size)
		return nil, errors.New("invalid key size")
	}
	engine := PresentEngine{}
	engine.BlockEngine = *NewBlockEngine("present", sharedSecret)
	engine.SharedSecret = sharedSecret[:size/8]
	engine.logger = configs.InitLogger("present")
	return &engine, nil
}

func (e *PresentEngine) GetName() string {
	return e.EngineData.Name
}

func (e *PresentEngine) GetType() string {
	return e.EngineData.Type
}

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
