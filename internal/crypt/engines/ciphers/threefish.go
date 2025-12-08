package ciphers

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"github.com/schultz-is/go-threefish"
	"github.com/sem-hub/snake-net/internal/crypt/engines"
	"golang.org/x/crypto/hkdf"
)

const tweakSize = 16

type ThreefishEngine struct {
	modes        *Modes
	SharedSecret []byte
	tweak        []byte
	keySize      int
}

func NewThreefishEngine(sharedSecret []byte, size int, mode string) (*ThreefishEngine, error) {
	if engines.ModeList[mode] == "aead" {
		return nil, errors.New("threefish cipher does not support aead modes (BlockSize > 16)")
	}

	allowedKeySizes := []int{256, 512, 1024}
	if size == 0 {
		size = 256
	}

	engine := ThreefishEngine{}
	var err error

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
	engine.modes, err = NewModes("threefish", mode, size, allowedKeySizes, engine.SharedSecret,
		engine.NewCipher, engine.BlockSize)
	if err != nil {
		return nil, err
	}
	engine.keySize = size

	return &engine, nil
}

func (e *ThreefishEngine) GetName() string {
	return e.modes.Name
}

func (e *ThreefishEngine) GetType() string {
	return e.modes.Type
}
func (e *ThreefishEngine) BlockSize() int {
	blockSize := 0
	switch e.keySize {
	case 256:
		blockSize = 32
	case 512:
		blockSize = 64
	case 1024:
		blockSize = 128
	}
	return blockSize
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
	e.tweak = make([]byte, tweakSize)
	rand.Read(e.tweak)
	chiperData, err := e.modes.Encrypt(data)
	if err != nil {
		return nil, err
	}
	chiperData = append(e.tweak, chiperData...)
	return chiperData, nil
}

func (e *ThreefishEngine) Decrypt(data []byte) ([]byte, error) {
	e.tweak = data[:tweakSize]
	data = data[tweakSize:]
	return e.modes.Decrypt(data)
}
