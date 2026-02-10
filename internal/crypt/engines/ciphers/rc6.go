//go:build rc6

package ciphers

import (
	"crypto/cipher"

	rc6 "github.com/CampNowhere/golang-rc6"
	"github.com/sem-hub/snake-net/internal/crypt/engines"
)

func init() {
	engines.RegisterEngine("rc6", func(sharedSecret []byte, keySize int, mode string) (engines.CryptoEngine, error) {
		return NewRc6Engine(sharedSecret, keySize, mode)
	})
}

type Rc6Engine struct {
	modes *Modes
}

func NewRc6Engine(sharedSecret []byte, size int, mode string) (*Rc6Engine, error) {
	engine := Rc6Engine{}

	allowedKeySizes := []int{128, 192, 256}
	if size == 0 {
		size = 256
	}
	var err error
	engine.modes, err = NewModes("RC6", mode, size, allowedKeySizes, sharedSecret,
		engine.NewCipher, engine.BlockSize)
	if err != nil {
		return nil, err
	}
	return &engine, nil
}

func (e *Rc6Engine) GetKeySizes() []int {
	return e.modes.GetKeySizes()
}

func (e *Rc6Engine) GetName() string {
	return e.modes.GetName()
}

func (e *Rc6Engine) GetType() string {
	return e.modes.GetType()
}

func (e *Rc6Engine) BlockSize() int {
	return 16
}

func (e *Rc6Engine) NewCipher() (cipher.Block, error) {
	return rc6.NewCipher(e.modes.SharedSecret), nil
}

func (e *Rc6Engine) Encrypt(data []byte) ([]byte, error) {
	return e.modes.Encrypt(data)
}

func (e *Rc6Engine) Decrypt(data []byte) ([]byte, error) {
	return e.modes.Decrypt(data)
}
