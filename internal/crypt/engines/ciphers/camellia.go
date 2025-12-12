package ciphers

import (
	"crypto/cipher"

	"github.com/aead/camellia"
)

type CamelliaEngine struct {
	modes *Modes
}

func NewCamelliaEngine(sharedSecret []byte, size int, mode string) (*CamelliaEngine, error) {
	engine := CamelliaEngine{}

	allowedKeySizes := []int{128, 192, 256}
	if size == 0 {
		size = 256
	}
	var err error
	engine.modes, err = NewModes("camel", mode, size, allowedKeySizes, sharedSecret,
		engine.NewCipher, engine.BlockSize)
	if err != nil {
		return nil, err
	}
	return &engine, nil
}

func (e *CamelliaEngine) GetKeySizes() []int {
	return e.modes.GetKeySizes()
}

func (e *CamelliaEngine) GetName() string {
	return e.modes.GetName()
}

func (e *CamelliaEngine) GetType() string {
	return e.modes.GetType()
}

func (e *CamelliaEngine) BlockSize() int {
	return camellia.BlockSize
}

func (e *CamelliaEngine) NewCipher() (cipher.Block, error) {
	return camellia.NewCipher(e.modes.SharedSecret)
}

func (e *CamelliaEngine) Encrypt(data []byte) ([]byte, error) {
	return e.modes.Encrypt(data)
}

func (e *CamelliaEngine) Decrypt(data []byte) ([]byte, error) {
	return e.modes.Decrypt(data)
}
