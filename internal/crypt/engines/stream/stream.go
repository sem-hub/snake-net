package stream

import (
	"crypto/cipher"
	"crypto/rand"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/crypt/engines"
)

type StreamEngine struct {
	engines.EngineData
}

func NewStreamEngine(name string) *StreamEngine {
	engine := StreamEngine{}
	engine.EngineData = *engines.NewEngineData(name, "stream")
	engine.Logger = configs.InitLogger("crypt")
	return &engine
}

func (e *StreamEngine) StreamEncrypt(addBlockSize int, newStream func([]byte) (cipher.Stream, error), data []byte) ([]byte, error) {
	e.Logger.Trace("Encrypt stream", "datalen", len(data))

	iv := make([]byte, addBlockSize)
	_, _ = rand.Read(iv)
	stream, err := newStream(iv)
	if err != nil {
		return nil, err
	}

	bufOut := make([]byte, len(data)+len(iv))
	// copy iv to output buf
	copy(bufOut[:addBlockSize], iv)

	stream.XORKeyStream(bufOut[addBlockSize:], data)
	e.Logger.Trace("Encrypt stream", "encryptedlen", len(bufOut))
	return bufOut, nil
}

func (e *StreamEngine) StreamDecrypt(addBlockSize int, newStream func([]byte) (cipher.Stream, error), data []byte) ([]byte, error) {
	e.Logger.Trace("Decrypt stream", "datalen", len(data))

	iv := data[:addBlockSize]
	stream, err := newStream(iv)
	if err != nil {
		return nil, err
	}
	bufOut := make([]byte, len(data)-len(iv))

	stream.XORKeyStream(bufOut, data[addBlockSize:])
	e.Logger.Trace("Decrypt stream", "decryptedlen", len(bufOut))
	return bufOut, nil
}
