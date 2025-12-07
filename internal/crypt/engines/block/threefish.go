package block

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"

	"github.com/schultz-is/go-threefish"
	"github.com/sem-hub/snake-net/internal/configs"
	"golang.org/x/crypto/hkdf"
)

const tweakSize = 16

type ThreefishEngine struct {
	BlockEngine
	SharedSecret []byte
	logger       *slog.Logger
	tweak        []byte
	keySize      int
}

func NewThreefishEngine(sharedSecret []byte, size int) (*ThreefishEngine, error) {
	allowedKeySizes := []int{256, 512, 1024}
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
		logger := configs.InitLogger("threefish")
		logger.Error("Invalid key size for Threefish", "size", size)
		return nil, errors.New("invalid key size")
	}

	engine := ThreefishEngine{}
	engine.BlockEngine = *NewBlockEngine("threefish")
	engine.keySize = size

	// Expand key if size > 256 bits
	if size > 256 {
		engine.SharedSecret = make([]byte, size/8)
		reader := hkdf.New(sha256.New, []byte(engine.SharedSecret), nil, nil)
		_, err := io.ReadFull(reader, engine.SharedSecret)
		if err != nil {
			return nil, err
		}
	} else {
		engine.SharedSecret = sharedSecret
	}
	engine.logger = configs.InitLogger("threefish")
	return &engine, nil
}

func (e *ThreefishEngine) GetName() string {
	return e.BlockEngine.Name
}

func (e *ThreefishEngine) GetType() string {
	return e.BlockEngine.Type
}

func (e *ThreefishEngine) NewCipher() (cipher.Block, error) {
	switch e.keySize {
	case 256:
		return threefish.New256(e.SharedSecret, e.tweak)
	case 512:
		return threefish.New512(e.SharedSecret, e.tweak)
	case 1024:
		return threefish.New1024(e.SharedSecret, e.tweak)
	}
	return nil, errors.New("invalid key size for Threefish")
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
