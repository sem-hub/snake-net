//go:build speck

package ciphers

import (
	"crypto/cipher"

	"github.com/deatil/go-cryptobin/cipher/speck"
	"github.com/sem-hub/snake-net/internal/crypt/engines"
)

func init() {
	engines.RegisterEngine("speck", func(sharedSecret []byte, keySize int, mode string) (engines.CryptoEngine, error) {
		return NewSpeckEngine(sharedSecret, keySize, mode)
	})
}

type SpeckEngine struct {
	modes *Modes
}

func NewSpeckEngine(sharedSecret []byte, size int, mode string) (*SpeckEngine, error) {
	engine := SpeckEngine{}

	allowedKeySizes := []int{128, 192, 256}
	if size == 0 {
		size = 256
	}
	var err error
	engine.modes, err = NewModes("speck", mode, size, allowedKeySizes, sharedSecret,
		engine.NewCipher, engine.BlockSize)
	if err != nil {
		return nil, err
	}
	return &engine, nil
}

func (e *SpeckEngine) GetKeySizes() []int {
	return e.modes.GetKeySizes()
}

func (e *SpeckEngine) GetName() string {
	return e.modes.GetName()
}

func (e *SpeckEngine) GetType() string {
	return e.modes.GetType()
}

func (e *SpeckEngine) BlockSize() int {
	return speck.BlockSize
}

func (e *SpeckEngine) NewCipher() (cipher.Block, error) {
	return speck.NewCipher(e.modes.SharedSecret)
}

func (e *SpeckEngine) Encrypt(data []byte) ([]byte, error) {
	return e.modes.Encrypt(data)
}

func (e *SpeckEngine) Decrypt(data []byte) ([]byte, error) {
	return e.modes.Decrypt(data)
}
