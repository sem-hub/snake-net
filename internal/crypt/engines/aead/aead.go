package aead

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/crypt/engines"
)

type AeadEngine struct {
	engines.EngineData
	aead cipher.AEAD
}

func NewAeadEngine(name string, aead cipher.AEAD) *AeadEngine {
	engine := AeadEngine{}
	engine.EngineData = *engines.NewEngineData(name, "aead")
	engine.Logger = configs.GetLogger("crypt")
	engine.aead = aead
	return &engine
}

func (e *AeadEngine) Seal(data []byte) ([]byte, error) {
	e.Logger.Trace("Encrypt AEAD", "datalen", len(data))
	nonce := make([]byte, e.aead.NonceSize())
	_, _ = rand.Read(nonce)
	bufOut := e.aead.Seal(nil, nonce, data, nil)

	e.Logger.Trace("Encrypt AEAD", "encryptedlen", len(bufOut), "noncelen", len(nonce))
	bufOut = append(nonce, bufOut...)
	return bufOut, nil
}

func (e *AeadEngine) Open(data []byte) ([]byte, error) {
	e.Logger.Trace("Decrypt AEAD", "datalen", len(data))
	nonceSize := e.aead.NonceSize()
	e.Logger.Trace("Decrypt AEAD", "noncesize", nonceSize, "overhead", e.aead.Overhead())
	if len(data) < nonceSize {
		return nil, errors.New("data is too short")
	}

	nonce, dataEnc := data[:nonceSize], data[nonceSize:]
	bufOut, err := e.aead.Open(nil, nonce, dataEnc, nil)
	e.Logger.Trace("Decrypt AEAD", "decryptedlen", len(bufOut))
	return bufOut, err
}

func (e *AeadEngine) GetOverhead() int {
	return e.aead.NonceSize() + e.aead.Overhead()
}
