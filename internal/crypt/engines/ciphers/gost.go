package ciphers

import (
	"crypto/cipher"
	"errors"

	"github.com/rmuch/gost"
	"github.com/sem-hub/snake-net/internal/crypt/engines"
)

// GOST28147-89 block cipher engine. ParamZ aka Magma.
type GostEngine struct {
	modes *Modes
}

// Only 256 bits key size
func NewGostEngine(sharedSecret []byte, mode string) (*GostEngine, error) {
	if engines.ModeList[mode] == "aead" && mode != "mgm" && mode != "eax" {
		return nil, errors.New("gost cipher does not support aead modes (BlockSize < 16)")
	}
	engine := GostEngine{}

	allowedKeySizes := []int{256}
	var err error
	engine.modes, err = NewModes("gost", mode, 256, allowedKeySizes, sharedSecret,
		engine.NewCipher, engine.BlockSize)
	if err != nil {
		return nil, err
	}
	return &engine, nil
}

func (e *GostEngine) GetName() string {
	return e.modes.GetName()
}

func (e *GostEngine) GetType() string {
	return e.modes.GetType()
}

func (e *GostEngine) BlockSize() int {
	return gost.BlockSize
}

func (e *GostEngine) NewCipher() (cipher.Block, error) {
	return gost.NewBlockCipher(e.modes.SharedSecret, gost.SboxIdtc26gost28147paramZ)
}

func (e *GostEngine) Encrypt(data []byte) ([]byte, error) {
	return e.modes.Encrypt(data)
}

func (e *GostEngine) Decrypt(data []byte) ([]byte, error) {
	return e.modes.Decrypt(data)
}
