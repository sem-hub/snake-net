//go:build aegis

package aead

import (
	"crypto/cipher"

	"github.com/aegis-aead/go-libaegis/aegis128l"
	"github.com/sem-hub/snake-net/internal/crypt/engines"
)

func init() {
	engines.RegisterEngine("aegis", func(sharedSecret []byte, keySize int, mode string) (engines.CryptoEngine, error) {
		return NewAegisEngine(sharedSecret)
	})
}

type AegisEngine struct {
	AeadEngine
	SharedSecret []byte
}

// Implementing the AEGIS family. Only 128 bits key size
func NewAegisEngine(sharedSecret []byte) (*AegisEngine, error) {
	engine := AegisEngine{}
	engine.AeadEngine = *NewAeadEngine("aegis")
	engine.SharedSecret = sharedSecret[:16]
	return &engine, nil
}

func (e *AegisEngine) GetKeySizes() []int {
	return []int{128}
}

func (e *AegisEngine) GetName() string {
	return e.EngineData.Name
}

func (e *AegisEngine) GetType() string {
	return e.EngineData.Type
}

func (e *AegisEngine) NewAEAD() (cipher.AEAD, error) {
	return aegis128l.New(e.SharedSecret, 16)
}

func (e *AegisEngine) Encrypt(data []byte) ([]byte, error) {
	return e.AeadEngine.Seal(e.NewAEAD, data)
}

func (e *AegisEngine) Decrypt(data []byte) ([]byte, error) {
	return e.AeadEngine.Open(e.NewAEAD, data)
}

func (e *AegisEngine) GetOverhead() int {
	return 16 + aegis128l.NonceSize // tag size + nonce size
}
