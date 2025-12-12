package ciphers

import (
	"crypto/cipher"

	"golang.org/x/crypto/twofish"
)

type TwofishEngine struct {
	modes *Modes
}

func NewTwofishEngine(sharedSecret []byte, size int, mode string) (*TwofishEngine, error) {
	engine := TwofishEngine{}

	allowedKeySizes := []int{128, 192, 256}
	if size == 0 {
		size = 256
	}
	var err error
	engine.modes, err = NewModes("twofish", mode, size, allowedKeySizes, sharedSecret,
		engine.NewCipher, engine.BlockSize)
	if err != nil {
		return nil, err
	}
	return &engine, nil
}

func (e *TwofishEngine) GetKeySizes() []int {
	return e.modes.GetKeySizes()
}

func (e *TwofishEngine) GetName() string {
	return e.modes.GetName()
}

func (e *TwofishEngine) GetType() string {
	return e.modes.GetType()
}

func (e *TwofishEngine) BlockSize() int {
	return 16
}

func (e *TwofishEngine) NewCipher() (cipher.Block, error) {
	return twofish.NewCipher(e.modes.SharedSecret)
}

func (e *TwofishEngine) Encrypt(data []byte) ([]byte, error) {
	return e.modes.Encrypt(data)
}

func (e *TwofishEngine) Decrypt(data []byte) ([]byte, error) {
	return e.modes.Decrypt(data)
}
