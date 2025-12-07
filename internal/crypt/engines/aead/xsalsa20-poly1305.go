package aead

import (
	"crypto/cipher"
	"errors"

	"github.com/sem-hub/snake-net/internal/configs"
	"golang.org/x/crypto/nacl/secretbox"
)

type Xsalsa20Poly1305Engine struct {
	AeadEngine
	SharedSecret []byte
}

type Xsalsa20Poly1305 struct {
	cipher.AEAD
	key [32]byte
}

func NewXsalsa20Poly1305(key []byte) *Xsalsa20Poly1305 {
	var k [32]byte
	copy(k[:], key)
	return &Xsalsa20Poly1305{key: k}
}

func (x *Xsalsa20Poly1305) NonceSize() int {
	return 24
}

func (x *Xsalsa20Poly1305) Overhead() int {
	return 16
}

func (x *Xsalsa20Poly1305) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	nonceArray := [24]byte{}
	copy(nonceArray[:], nonce)
	return secretbox.Seal(dst, plaintext, &nonceArray, &x.key)
}

func (x *Xsalsa20Poly1305) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	nonceArray := [24]byte{}
	copy(nonceArray[:], nonce)
	plaintext, ok := secretbox.Open(dst, ciphertext, &nonceArray, &x.key)
	if !ok {
		return nil, errors.New("xsalsa20poly1305: decryption error")
	}
	return plaintext, nil
}

func NewXsalsa20Poly1305Engine(sharedSecret []byte) (*Xsalsa20Poly1305Engine, error) {
	engine := Xsalsa20Poly1305Engine{}
	engine.AeadEngine = *NewAeadEngine("xsalsa20poly1305")
	engine.SharedSecret = sharedSecret
	engine.logger = configs.InitLogger("xsalsa20poly1305")
	return &engine, nil
}

func (e *Xsalsa20Poly1305Engine) GetName() string {
	return e.AeadEngine.Name
}

func (e *Xsalsa20Poly1305Engine) GetType() string {
	return e.AeadEngine.Type
}

func (e *Xsalsa20Poly1305Engine) NewAEAD() (cipher.AEAD, error) {
	return NewXsalsa20Poly1305(e.SharedSecret), nil
}

func (e *Xsalsa20Poly1305Engine) Encrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Seal", "datalen", len(data))
	return e.AeadEngine.Seal(e.NewAEAD, data)
}

func (e *Xsalsa20Poly1305Engine) Decrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Open", "datalen", len(data))
	return e.AeadEngine.Open(e.NewAEAD, data)
}
