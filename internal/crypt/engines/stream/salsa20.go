//go:build salsa20

package stream

import (
	"crypto/rand"

	"github.com/sem-hub/snake-net/internal/crypt/engines"
	"golang.org/x/crypto/salsa20"
)

func init() {
	engines.RegisterEngine("salsa20", func(sharedSecret []byte, keySize int, mode string) (engines.CryptoEngine, error) {
		return NewSalsa20Engine(sharedSecret)
	})
}

type Salsa20Engine struct {
	StreamEngine
	SharedSecret []byte
}

func NewSalsa20Engine(sharedSecret []byte) (*Salsa20Engine, error) {
	engine := Salsa20Engine{}
	engine.StreamEngine = *NewStreamEngine("salsa20")
	engine.SharedSecret = sharedSecret
	return &engine, nil
}

func (e *Salsa20Engine) GetKeySizes() []int {
	return []int{256}
}

func (e *Salsa20Engine) GetName() string {
	return e.EngineData.Name
}

func (e *Salsa20Engine) GetType() string {
	return e.EngineData.Type
}

func (e *Salsa20Engine) Encrypt(data []byte) ([]byte, error) {
	//e.Logger.Debug("Encrypt", "datalen", len(data))

	nonce := make([]byte, 8)
	_, _ = rand.Read(nonce)

	bufOut := make([]byte, len(nonce)+len(data))
	// copy nonce to output buf
	copy(bufOut[:8], nonce)

	// secret must be array not slice
	var secret [32]byte
	copy(secret[:], e.SharedSecret)
	salsa20.XORKeyStream(bufOut[8:], data, nonce, &secret)

	//e.Logger.Debug("Encrypt", "encryptedlen", len(bufOut))
	return bufOut, nil
}

func (e *Salsa20Engine) Decrypt(data []byte) ([]byte, error) {
	//e.Logger.Debug("Decrypt", "datalen", len(data))

	nonce := data[:8]
	data = data[8:]

	//e.Logger.Debug("Decrypt", "decryptedlen", len(data))
	bufOut := make([]byte, len(data))
	// secret must be array not slice
	var secret [32]byte
	copy(secret[:], e.SharedSecret)
	salsa20.XORKeyStream(bufOut, data, nonce, &secret)
	return bufOut, nil
}
