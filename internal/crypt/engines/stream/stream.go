package stream

import (
	"crypto/cipher"
	"crypto/rand"
	"log/slog"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/crypt/engines"
)

type StreamEngine struct {
	engines.EngineData
	SharedSecret []byte
	logger       *slog.Logger
}

func NewStreamEngine(sharedSecret []byte) *StreamEngine {
	engine := StreamEngine{}
	engine.EngineData = *engines.NewEngineData("aes", "stream")
	engine.SharedSecret = sharedSecret
	engine.logger = configs.InitLogger("aes")
	return &engine
}

func (e *StreamEngine) Encrypt(block cipher.Block, newStream func(cipher.Block, []byte) cipher.Stream, data []byte) ([]byte, error) {
	e.logger.Debug("Encrypt stream", "datalen", len(data))

	iv := make([]byte, block.BlockSize())
	rand.Read(iv)
	stream := newStream(block, iv)

	bufOut := make([]byte, len(data)+len(iv))
	// copy iv to output buf
	copy(bufOut[:block.BlockSize()], iv)

	stream.XORKeyStream(bufOut[block.BlockSize():], data)
	e.logger.Debug("Encrypt stream", "encryptedlen", len(bufOut))
	return bufOut, nil
}

func (e *StreamEngine) Decrypt(block cipher.Block, newStream func(cipher.Block, []byte) cipher.Stream, data []byte) ([]byte, error) {
	e.logger.Debug("Decrypt stream", "datalen", len(data))

	iv := make([]byte, block.BlockSize())
	copy(iv, data[:block.BlockSize()])
	stream := newStream(block, iv)

	bufOut := make([]byte, len(data)-len(iv))

	stream.XORKeyStream(bufOut, data[block.BlockSize():])
	e.logger.Debug("Decrypt stream", "decryptedlen", len(bufOut))

	return bufOut, nil
}
