package aead

import (
	"crypto/cipher"

	"golang.org/x/crypto/chacha20poly1305"
)

type Chacha20Poly1305Engine struct {
	AeadEngine
	SharedSecret []byte
}

func NewChacha20Poly1305Engine(sharedSecret []byte) (*Chacha20Poly1305Engine, error) {
	engine := Chacha20Poly1305Engine{}
	engine.AeadEngine = *NewAeadEngine("chacha20poly1305")
	engine.SharedSecret = sharedSecret
	return &engine, nil
}

func (e *Chacha20Poly1305Engine) GetKeySizes() []int {
	return []int{256}
}

func (e *Chacha20Poly1305Engine) GetName() string {
	return e.EngineData.Name
}

func (e *Chacha20Poly1305Engine) GetType() string {
	return e.EngineData.Type
}

func (e *Chacha20Poly1305Engine) NewAEAD() (cipher.AEAD, error) {
	return chacha20poly1305.New(e.SharedSecret)
}

func (e *Chacha20Poly1305Engine) Encrypt(data []byte) ([]byte, error) {
	return e.AeadEngine.Seal(e.NewAEAD, data)
}

func (e *Chacha20Poly1305Engine) Decrypt(data []byte) ([]byte, error) {
	return e.AeadEngine.Open(e.NewAEAD, data)
}
