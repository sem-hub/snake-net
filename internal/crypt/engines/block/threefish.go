package block

import (
	"crypto/cipher"
	"crypto/rand"
	"log/slog"

	"github.com/schultz-is/go-threefish"
	"github.com/sem-hub/snake-net/internal/configs"
)

type ThreefishEngine struct {
	BlockEngine
	logger *slog.Logger
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

func (e *ThreefishEngine) NewCipher(secret, tweak []byte) (cipher.Block, error) {
	return threefish.New256(secret, tweak)
}

func (e *ThreefishEngine) Encrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Encrypt", "datalen", len(data))
	tweak := make([]byte, 16)
	rand.Read(tweak)
	block, err := e.NewCipher(e.SharedSecret, tweak)
	if err != nil {
		return nil, err
	}
	chiperData, err := e.BlockEngine.Encrypt(block, cipher.NewCBCEncrypter, data)
	if err != nil {
		return nil, err
	}
	chiperData = append(tweak, chiperData...)
	return chiperData, nil
}

func (e *ThreefishEngine) Decrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Decrypt", "datalen", len(data))
	tweak := data[:16]
	data = data[16:]
	block, err := e.NewCipher(e.SharedSecret, tweak)
	if err != nil {
		return nil, err
	}
	return e.BlockEngine.Decrypt(block, cipher.NewCBCDecrypter, data)
}
