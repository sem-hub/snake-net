package stream

import (
	"crypto/cipher"

	"github.com/ebfe/estream/rabbit"
)

type RabbitEngine struct {
	StreamEngine
	SharedSecret []byte
	ivSize       int
}

// Only 128 bits key size
func NewRabbitEngine(sharedSecret []byte) (*RabbitEngine, error) {
	engine := RabbitEngine{}
	engine.StreamEngine = *NewStreamEngine("rabbit")
	engine.ivSize = 8
	engine.SharedSecret = sharedSecret[:16]
	return &engine, nil
}

func (e *RabbitEngine) GetKeySizes() []int {
	return []int{128}
}

func (e *RabbitEngine) GetName() string {
	return e.EngineData.Name
}

func (e *RabbitEngine) GetType() string {
	return e.EngineData.Type
}

func (e *RabbitEngine) NewStream(iv []byte) (cipher.Stream, error) {
	return rabbit.NewCipher(e.SharedSecret, iv)
}

func (e *RabbitEngine) Encrypt(data []byte) ([]byte, error) {
	return e.StreamEngine.StreamEncrypt(e.ivSize, e.NewStream, data)
}

func (e *RabbitEngine) Decrypt(data []byte) ([]byte, error) {
	return e.StreamEngine.StreamDecrypt(e.ivSize, e.NewStream, data)
}
