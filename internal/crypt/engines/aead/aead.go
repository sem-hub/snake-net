package aead

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"log/slog"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/crypt/engines"
)

type AeadEngine struct {
	engines.EngineData
	SharedSecret []byte
	logger       *slog.Logger
}

func NewAeadEngine(name string, sharedSecret []byte) *AeadEngine {
	engine := AeadEngine{}
	engine.EngineData = *engines.NewEngineData(name, "aead")
	engine.SharedSecret = sharedSecret
	engine.logger = configs.InitLogger("aead")
	return &engine
}

func (e *AeadEngine) Encrypt(block cipher.Block, newStream func(cipher.Block) (cipher.AEAD, error),
	data []byte) ([]byte, error) {
	e.logger.Debug("Encrypt AEAD", "datalen", len(data))

	stream, err := newStream(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, stream.NonceSize())
	rand.Read(nonce)
	bufOut := stream.Seal(nil, nonce, data, nil)

	e.logger.Debug("Encrypt AEAD", "encryptedlen", len(bufOut), "noncelen", len(nonce))
	bufOut = append(nonce, bufOut...)
	return bufOut, nil
}

func (e *AeadEngine) Decrypt(block cipher.Block, newStream func(cipher.Block) (cipher.AEAD, error),
	data []byte) ([]byte, error) {
	e.logger.Debug("Decrypt AEAD", "datalen", len(data))

	stream, err := newStream(block)
	if err != nil {
		return nil, err
	}

	nonceSize := stream.NonceSize()
	e.logger.Debug("Decrypt AEAD", "noncesize", nonceSize)
	if len(data) < nonceSize {
		return nil, errors.New("data is too short")
	}

	nonce, dataEnc := data[:nonceSize], data[nonceSize:]
	bufOut, err := stream.Open(nil, nonce, dataEnc, nil)
	e.logger.Debug("Decrypt AEAD", "decryptedlen", len(bufOut))
	return bufOut, err
}
