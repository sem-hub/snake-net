package ciphers

import (
	"crypto/cipher"
	"errors"
	"github.com/dgryski/go-idea"

	"github.com/sem-hub/snake-net/internal/crypt/engines"
)

// IDEA block cipher engine
type IdeaEngine struct {
	modes *Modes
}

// Only 128 bits key size
func NewIdeaEngine(sharedSecret []byte, mode string) (*IdeaEngine, error) {
	if engines.ModeList[mode] == "aead" {
		return nil, errors.New("idea cipher does not support aead modes")
	}
	engine := IdeaEngine{}

	allowedKeySizes := []int{128}
	var err error
	engine.modes, err = NewModes("idea", mode, 128, allowedKeySizes, sharedSecret,
		engine.NewCipher, engine.BlockSize)
	if err != nil {
		return nil, err
	}
	return &engine, nil
}

func (e *IdeaEngine) GetName() string {
	return e.modes.GetName()
}

func (e *IdeaEngine) GetType() string {
	return e.modes.GetType()
}

func (e *IdeaEngine) BlockSize() int {
	return 8
}

func (e *IdeaEngine) NewCipher() (cipher.Block, error) {
	return idea.NewCipher(e.modes.SharedSecret)
}

func (e *IdeaEngine) Encrypt(data []byte) ([]byte, error) {
	return e.modes.Encrypt(data)
}

func (e *IdeaEngine) Decrypt(data []byte) ([]byte, error) {
	return e.modes.Decrypt(data)
}
