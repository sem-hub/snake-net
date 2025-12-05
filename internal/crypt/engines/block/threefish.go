package block

import (
	"crypto/cipher"
	"crypto/rand"
	"log/slog"

	"github.com/schultz-is/go-threefish"
	"github.com/sem-hub/snake-net/internal/configs"
)

const tweakSize = 16

type ThreefishEngine struct {
	BlockEngine
	logger *slog.Logger
	tweak  []byte
}

func NewThreefishEngine(sharedSecret []byte) *ThreefishEngine {
	engine := ThreefishEngine{}
	engine.BlockEngine = *NewBlockEngine("threefish", sharedSecret)
	engine.SharedSecret = sharedSecret
	engine.logger = configs.InitLogger("threefish")
	return &engine
}

func (e *ThreefishEngine) GetName() string {
	return e.EngineData.Name
}

func (e *ThreefishEngine) GetType() string {
	return e.EngineData.Type
}

func (e *ThreefishEngine) NewCipher() (cipher.Block, error) {
	return threefish.New256(e.SharedSecret, e.tweak)
}

func (e *ThreefishEngine) Encrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Encrypt", "datalen", len(data))
	e.tweak = make([]byte, tweakSize)
	rand.Read(e.tweak)
	chiperData, err := e.BlockEngine.BlockEncrypt(e.NewCipher, data)
	if err != nil {
		return nil, err
	}
	chiperData = append(e.tweak, chiperData...)
	return chiperData, nil
}

func (e *ThreefishEngine) Decrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Decrypt", "datalen", len(data))
	e.tweak = data[:tweakSize]
	data = data[tweakSize:]
	return e.BlockEngine.BlockDecrypt(e.NewCipher, data)
}
