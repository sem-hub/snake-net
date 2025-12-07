package stream

import (
	"crypto/cipher"

	"github.com/ebfe/estream/rabbit"
)

const ivSize = 8

type RabbitEngine struct {
	StreamEngine
	SharedSecret []byte
}

// Only 128 bits key size
func NewRabbitEngine(sharedSecret []byte) (*RabbitEngine, error) {
	engine := RabbitEngine{}
	engine.StreamEngine = *NewStreamEngine("rabbit")
	engine.SharedSecret = sharedSecret[:16]
	return &engine, nil
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
	e.Logger.Debug("Encrypt", "datalen", len(data))
	return e.StreamEngine.StreamEncrypt(ivSize, e.NewStream, data)
}

func (e *RabbitEngine) Decrypt(data []byte) ([]byte, error) {
	e.Logger.Debug("Decrypt", "datalen", len(data))
	return e.StreamEngine.StreamDecrypt(ivSize, e.NewStream, data)
}
