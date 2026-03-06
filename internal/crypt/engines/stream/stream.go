package stream

import (
	"crypto/cipher"
	"crypto/rand"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/crypt/engines"
)

type StreamEngine struct {
	engines.EngineData
	blockSize int
}

func NewStreamEngine(name string, blockSize int) *StreamEngine {
	engine := StreamEngine{}
	engine.EngineData = *engines.NewEngineData(name, "stream")
	engine.Logger = configs.GetLogger("crypt")
	engine.blockSize = blockSize
	return &engine
}

func (e *StreamEngine) StreamEncrypt(newStream func([]byte) (cipher.Stream, error), data []byte) ([]byte, error) {
	e.Logger.Trace("Encrypt stream", "datalen", len(data))

	iv := make([]byte, e.blockSize)
	_, _ = rand.Read(iv)
	stream, err := newStream(iv)
	if err != nil {
		return nil, err
	}

	bufOut := make([]byte, len(data)+len(iv))
	// copy iv to output buf
	copy(bufOut[:e.blockSize], iv)

	stream.XORKeyStream(bufOut[e.blockSize:], data)
	e.Logger.Trace("Encrypt stream", "encryptedlen", len(bufOut))
	return bufOut, nil
}

func (e *StreamEngine) StreamDecrypt(newStream func([]byte) (cipher.Stream, error), data []byte) ([]byte, error) {
	e.Logger.Trace("Decrypt stream", "datalen", len(data))

	iv := data[:e.blockSize]
	stream, err := newStream(iv)
	if err != nil {
		return nil, err
	}
	bufOut := make([]byte, len(data)-len(iv))

	stream.XORKeyStream(bufOut, data[e.blockSize:])
	e.Logger.Trace("Decrypt stream", "decryptedlen", len(bufOut))
	return bufOut, nil
}

func (e *StreamEngine) GetOverhead() int {
	return e.blockSize // IV size
}
