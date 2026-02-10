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
	SharedSecret []byte
}

// Light waight AEAD cipher Grain. Only 128 bits key size
func NewGrainEngine(sharedSecret []byte) (*GrainEngine, error) {
	engine := GrainEngine{}
	engine.AeadEngine = *NewAeadEngine("grain")
	engine.SharedSecret = sharedSecret[:16]
	return &engine, nil
}

func (e *GrainEngine) GetKeySizes() []int {
	return []int{128}
}

func (e *GrainEngine) GetName() string {
	return e.EngineData.Name
}

func (e *GrainEngine) GetType() string {
	return e.EngineData.Type
}

func (e *GrainEngine) NewAEAD() (cipher.AEAD, error) {
	return grain.New(e.SharedSecret)
}

func (e *GrainEngine) Encrypt(data []byte) ([]byte, error) {
	return e.AeadEngine.Seal(e.NewAEAD, data)
}

func (e *GrainEngine) Decrypt(data []byte) ([]byte, error) {
	return e.AeadEngine.Open(e.NewAEAD, data)
}
