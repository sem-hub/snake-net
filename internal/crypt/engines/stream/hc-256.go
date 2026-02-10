//go:build hc256

package stream

import (
	"crypto/cipher"

	"github.com/pedroalbanese/crypto/hc256"
	"github.com/sem-hub/snake-net/internal/crypt/engines"
)

func init() {
	engines.RegisterEngine("hc", func(sharedSecret []byte, keySize int, mode string) (engines.CryptoEngine, error) {
		return NewHc256Engine(sharedSecret)
	})
}

type Hc256Engine struct {
	StreamEngine
	SharedSecret []byte
	nonceSize    int
}

// Only 128 bits key size
func NewHc256Engine(sharedSecret []byte) (*Hc256Engine, error) {
	engine := Hc256Engine{}
	engine.StreamEngine = *NewStreamEngine("hc-256")
	engine.nonceSize = 32
	engine.SharedSecret = sharedSecret[:16]
	return &engine, nil
}

func (e *Hc256Engine) GetKeySizes() []int {
	return []int{128}
}

func (e *Hc256Engine) GetName() string {
	return e.EngineData.Name
}

func (e *Hc256Engine) GetType() string {
	return e.EngineData.Type
}

func (e *Hc256Engine) NewStream(nonce []byte) (cipher.Stream, error) {
	var nonceArray [32]byte
	copy(nonceArray[:], nonce)
	var secret [32]byte
	copy(secret[:], e.SharedSecret)
	// hc256.NewCipher requires pointers to arrays, not slices
	return hc256.NewCipher(&nonceArray, &secret), nil
}

func (e *Hc256Engine) Encrypt(data []byte) ([]byte, error) {
	return e.StreamEngine.StreamEncrypt(e.nonceSize, e.NewStream, data)
}

func (e *Hc256Engine) Decrypt(data []byte) ([]byte, error) {
	return e.StreamEngine.StreamDecrypt(e.nonceSize, e.NewStream, data)
}
