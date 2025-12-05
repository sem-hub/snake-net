package stream

import (
	"crypto/rand"
	"log/slog"

	"github.com/ebfe/estream/rabbit"

	"github.com/sem-hub/snake-net/internal/configs"
)

const ivSize = 8

type RabbitEngine struct {
	StreamEngine
	logger *slog.Logger
}

func NewRabbitEngine(sharedSecret []byte) *RabbitEngine {
	engine := RabbitEngine{}
	engine.StreamEngine = *NewStreamEngine("rabbit", sharedSecret)
	engine.SharedSecret = sharedSecret[:16]
	engine.logger = configs.InitLogger("rabbit")
	return &engine
}

func (e *RabbitEngine) GetName() string {
	return e.EngineData.Name
}

func (e *RabbitEngine) GetType() string {
	return e.EngineData.Type
}

func (e *RabbitEngine) Encrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Encrypt", "datalen", len(data))
	iv := make([]byte, ivSize)
	rand.Read(iv)
	cipher, err := rabbit.NewCipher(e.SharedSecret, iv)
	if err != nil {
		return nil, err
	}
	bufOut := make([]byte, len(iv)+len(data))
	// copy nonce to output buf
	copy(bufOut[:ivSize], iv)

	cipher.XORKeyStream(bufOut[ivSize:], data)
	e.logger.Debug("Encrypt", "encryptedlen", len(bufOut))
	return bufOut, nil
}

func (e *RabbitEngine) Decrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Decrypt", "datalen", len(data))
	iv := make([]byte, ivSize)
	copy(iv, data[:ivSize])
	cipher, err := rabbit.NewCipher(e.SharedSecret, iv)
	if err != nil {
		return nil, err
	}
	bufOut := make([]byte, len(data)-ivSize)
	cipher.XORKeyStream(bufOut, data[ivSize:])
	e.logger.Debug("Decrypt", "decryptedlen", len(bufOut))
	return bufOut, nil
}
