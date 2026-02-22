package aead

import (
	"crypto/cipher"

	"github.com/sem-hub/snake-net/internal/crypt/engines"
	"golang.org/x/crypto/chacha20poly1305"
)

func init() {
	engines.RegisterEngine("chacha20poly1305", func(sharedSecret []byte, keySize int, mode string) (engines.CryptoEngine, error) {
		return NewChacha20Poly1305Engine(sharedSecret)
	})
}

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

func (e *Chacha20Poly1305Engine) GetOverhead() int {
	return 16 + chacha20poly1305.NonceSize // tag size + nonce size
}
