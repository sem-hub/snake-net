package ciphers

import (
	"crypto/aes"
	"crypto/cipher"
)

type AesEngine struct {
	modes *Modes
}

func NewAesEngine(sharedSecret []byte, size int, mode string) (*AesEngine, error) {
	engine := AesEngine{}

	allowedKeySizes := []int{128, 192, 256}
	if size == 0 {
		size = 256
	}
	var err error
	engine.modes, err = NewModes("aes", mode, size, allowedKeySizes, sharedSecret,
		engine.NewCipher, engine.BlockSize)
	if err != nil {
		return nil, err
	}
	return &engine, nil
}

func (e *AesEngine) GetName() string {
	return e.modes.GetName()
}

func (e *AesEngine) GetType() string {
	return e.modes.GetType()
}

func (e *AesEngine) BlockSize() int {
	return aes.BlockSize
}

func (e *AesEngine) NewCipher() (cipher.Block, error) {
	return aes.NewCipher(e.modes.SharedSecret)
}

func (e *AesEngine) Encrypt(data []byte) ([]byte, error) {
	return e.modes.Encrypt(data)
}

func (e *AesEngine) Decrypt(data []byte) ([]byte, error) {
	return e.modes.Decrypt(data)
}
