//go:build chacha20

package stream

import (
	"crypto/cipher"

	"github.com/sem-hub/snake-net/internal/crypt/engines"
	"golang.org/x/crypto/chacha20"
)

func init() {
	engines.RegisterEngine("chacha20", func(sharedSecret []byte, keySize int, mode string) (engines.CryptoEngine, error) {
		return NewChacha20Engine(sharedSecret)
	})
}

type Chacha20Engine struct {
	StreamEngine
	SharedSecret []byte
}

func NewChacha20Engine(sharedSecret []byte) (*Chacha20Engine, error) {
	engine := Chacha20Engine{}
	engine.StreamEngine = *NewStreamEngine("chacha20")
	engine.SharedSecret = sharedSecret
	return &engine, nil
}

func (e *Chacha20Engine) GetKeySizes() []int {
	return []int{256}
}

func (e *Chacha20Engine) GetName() string {
	return e.EngineData.Name
}

func (e *Chacha20Engine) GetType() string {
	return e.EngineData.Type
}

func (e *Chacha20Engine) NewCipher(nonce []byte) (cipher.Stream, error) {
	return chacha20.NewUnauthenticatedCipher(e.SharedSecret, nonce)
}

func (e *Chacha20Engine) Encrypt(data []byte) ([]byte, error) {
	return e.StreamEngine.StreamEncrypt(chacha20.NonceSize, e.NewCipher, data)
}

func (e *Chacha20Engine) Decrypt(data []byte) ([]byte, error) {
	return e.StreamEngine.StreamDecrypt(chacha20.NonceSize, e.NewCipher, data)

}

func (e *Chacha20Engine) GetOverhead() int {
	return chacha20.NonceSize
}
