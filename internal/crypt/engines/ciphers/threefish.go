//go:build threefish

package ciphers

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"github.com/schultz-is/go-threefish"
	"golang.org/x/crypto/hkdf"

	"github.com/sem-hub/snake-net/internal/crypt/engines"
)

func init() {
	engines.RegisterEngine("threefish", func(sharedSecret []byte, keySize int, mode string) (engines.CryptoEngine, error) {
		return NewThreefishEngine(sharedSecret, keySize, mode)
	})
}

const tweakSize = 16

type ThreefishEngine struct {
	modes        *Modes
	sharedSecret []byte
	keySize      int
	mode         string
}

// IMPORTANT: Threefish is a tweakable block cipher, so we need to generate a random tweak for each encryption operation
//
//	           and prepend it to the ciphertext. The same tweak must be used for decryption, so we need to extract it from
//				  the beginning of the ciphertext.
func NewThreefishEngine(sharedSecret []byte, size int, mode string) (*ThreefishEngine, error) {
	// Only EAX mode is supported for Threefish AEAD because of big block size
	if engines.ModesList[mode] == "aead" && mode != "eax" {
		return nil, errors.New("threefish cipher does not support aead modes (BlockSize > 16)")
	}

	allowedKeySizes := []int{256, 512, 1024}
	if size == 0 {
		size = 256
	}

	engine := ThreefishEngine{}
	engine.keySize = size
	engine.mode = mode
	var err error

	// Expand key if size > 256 bits
	if size > 256 {
		engine.sharedSecret = make([]byte, size/8)
		reader := hkdf.New(sha256.New, []byte(sharedSecret), nil, nil)
		_, err := io.ReadFull(reader, engine.sharedSecret)
		if err != nil {
			return nil, err
		}
	} else {
		engine.sharedSecret = sharedSecret
	}
	engine.modes, err = NewModes("threefish", mode, size, allowedKeySizes, sharedSecret,
		engine.NewCipher, engine.BlockSize)
	if err != nil {
		return nil, err
	}
	engine.modes.KeySize = size

	return &engine, nil
}

func (e *ThreefishEngine) GetKeySizes() []int {
	return e.modes.GetKeySizes()
}

func (e *ThreefishEngine) GetName() string {
	return e.modes.GetName()
}

func (e *ThreefishEngine) GetType() string {
	return e.modes.GetType()
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
	tweak := make([]byte, tweakSize)
	return e.newCipherWithTweak(tweak)
}

func (e *ThreefishEngine) newCipherWithTweak(tweak []byte) (cipher.Block, error) {
	switch e.keySize {
	case 256:
		return threefish.New256(e.sharedSecret, tweak)
	case 512:
		return threefish.New512(e.sharedSecret, tweak)
	case 1024:
		return threefish.New1024(e.sharedSecret, tweak)
	}
	return nil, errors.New("invalid key size for Threefish")
}

func (e *ThreefishEngine) newModesWithTweak(tweak []byte) (*Modes, error) {
	allowedKeySizes := []int{256, 512, 1024}
	return NewModes("threefish", e.mode, e.keySize, allowedKeySizes, e.sharedSecret,
		func() (cipher.Block, error) {
			return e.newCipherWithTweak(tweak)
		},
		e.BlockSize,
	)
}

func (e *ThreefishEngine) Encrypt(data []byte) ([]byte, error) {
	tweak := make([]byte, tweakSize)
	_, _ = rand.Read(tweak)
	modes, err := e.newModesWithTweak(tweak)
	if err != nil {
		return nil, err
	}
	chiperData, err := modes.Encrypt(data)
	if err != nil {
		return nil, err
	}
	chiperData = append(tweak, chiperData...)
	return chiperData, nil
}

func (e *ThreefishEngine) Decrypt(data []byte) ([]byte, error) {
	if len(data) < tweakSize {
		return nil, errors.New("data is too short")
	}
	tweak := data[:tweakSize]
	data = data[tweakSize:]
	modes, err := e.newModesWithTweak(tweak)
	if err != nil {
		return nil, err
	}
	return modes.Decrypt(data)
}

func (e *ThreefishEngine) GetOverhead() int {
	return tweakSize + e.modes.GetOverhead()
}
