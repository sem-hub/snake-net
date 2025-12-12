package ciphers

import (
	"crypto/cipher"

	"github.com/aead/serpent"
)

type SerpentEngine struct {
	modes *Modes
}

func NewSerpentEngine(sharedSecret []byte, size int, mode string) (*SerpentEngine, error) {
	engine := SerpentEngine{}

	allowedKeySizes := []int{128, 192, 256}
	if size == 0 {
		size = 256
	}
	var err error
	engine.modes, err = NewModes("Serpent", mode, size, allowedKeySizes, sharedSecret,
		engine.NewCipher, engine.BlockSize)
	if err != nil {
		return nil, err
	}
	return &engine, nil
}

func (e *SerpentEngine) GetKeySizes() []int {
	return e.modes.GetKeySizes()
}

func (e *SerpentEngine) GetName() string {
	return e.modes.GetName()
}

func (e *SerpentEngine) GetType() string {
	return e.modes.GetType()
}

func (e *SerpentEngine) BlockSize() int {
	return serpent.BlockSize
}

func (e *SerpentEngine) NewCipher() (cipher.Block, error) {
	return serpent.NewCipher(e.modes.SharedSecret)
}

func (e *SerpentEngine) Encrypt(data []byte) ([]byte, error) {
	return e.modes.Encrypt(data)
}

func (e *SerpentEngine) Decrypt(data []byte) ([]byte, error) {
	return e.modes.Decrypt(data)
}
