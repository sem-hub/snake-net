package ciphers

import (
	"crypto/cipher"
	"errors"

	present "github.com/yi-jiayu/PRESENT.go"

	"github.com/sem-hub/snake-net/internal/crypt/engines"
)

// PRESENT block cipher engine
type PresentEngine struct {
	modes *Modes
}

// Only 80 or 128 bits key size supported. Using 128 bits
func NewPresentEngine(sharedSecret []byte, size int, mode string) (*PresentEngine, error) {
	if engines.ModeList[mode] == "aead" && mode != "mgm" && mode != "eax" {
		return nil, errors.New("present cipher does not support this aead mode: " + mode)
	}
	engine := PresentEngine{}
	allowedKeySizes := []int{80, 128}
	if size == 0 {
		size = 128
	}
	var err error
	engine.modes, err = NewModes("present", mode, size, allowedKeySizes, sharedSecret,
		engine.NewCipher, engine.BlockSize)
	if err != nil {
		return nil, err
	}
	return &engine, nil
}

func (e *PresentEngine) GetName() string {
	return e.modes.GetName()
}

func (e *PresentEngine) GetType() string {
	return e.modes.GetType()
}

func (e *PresentEngine) BlockSize() int {
	return present.BlockSize
}

func (e *PresentEngine) NewCipher() (cipher.Block, error) {
	return present.NewCipher(e.modes.SharedSecret)
}

func (e *PresentEngine) Encrypt(data []byte) ([]byte, error) {
	return e.modes.Encrypt(data)
}

func (e *PresentEngine) Decrypt(data []byte) ([]byte, error) {
	return e.modes.Decrypt(data)
}
