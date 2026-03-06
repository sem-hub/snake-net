//go:build grain

package aead

import (
	"crypto/cipher"

	"github.com/ericlagergren/lwcrypto/grain"
	"github.com/sem-hub/snake-net/internal/crypt/engines"
)

func init() {
	engines.RegisterEngine("grain", func(sharedSecret []byte, keySize int, mode string) (engines.CryptoEngine, error) {
		return NewGrainEngine(sharedSecret)
	})
}

type GrainEngine struct {
	AeadEngine
	sharedSecret []byte
}

// Light waight AEAD cipher Grain. Only 128 bits key size
// IMPORTANT:
// Grain has a state in cipher.AEAD, so we need to create a new instance for each encryption/decryption operation for thread safety.
func NewGrainEngine(sharedSecret []byte) (*GrainEngine, error) {
	engine := GrainEngine{}
	engine.sharedSecret = sharedSecret[:grain.KeySize]
	aead, err := engine.NewAEAD()
	if err != nil {
		return nil, err
	}
	engine.AeadEngine = *NewAeadEngine("grain", aead)
	return &engine, nil
}

func (e *GrainEngine) GetKeySizes() []int {
	return []int{grain.KeySize * 8}
}

func (e *GrainEngine) GetName() string {
	return e.AeadEngine.Name
}

func (e *GrainEngine) GetType() string {
	return e.AeadEngine.Type
}

func (e *GrainEngine) NewAEAD() (cipher.AEAD, error) {
	return grain.New(e.sharedSecret)
}

func (e *GrainEngine) Encrypt(data []byte) ([]byte, error) {
	aead, err := e.NewAEAD()
	if err != nil {
		return nil, err
	}
	return NewAeadEngine("grain", aead).Seal(data)
}

func (e *GrainEngine) Decrypt(data []byte) ([]byte, error) {
	aead, err := e.NewAEAD()
	if err != nil {
		return nil, err
	}
	return NewAeadEngine("grain", aead).Open(data)
}

func (e *GrainEngine) GetOverhead() int {
	return grain.TagSize + grain.NonceSize // tag size + nonce size
}
