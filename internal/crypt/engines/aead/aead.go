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
}

func NewAeadEngine(name string) *AeadEngine {
	engine := AeadEngine{}
	engine.EngineData = *engines.NewEngineData(name, "aead")
	engine.Logger = configs.InitLogger("crypt")
	return &engine
}

func (e *AeadEngine) Seal(NewAEAD func() (cipher.AEAD, error), data []byte) ([]byte, error) {
	e.Logger.Trace("Encrypt AEAD", "datalen", len(data))
	aead, err := NewAEAD()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	_, _ = rand.Read(nonce)
	bufOut := aead.Seal(nil, nonce, data, nil)

	e.Logger.Trace("Encrypt AEAD", "encryptedlen", len(bufOut), "noncelen", len(nonce))
	bufOut = append(nonce, bufOut...)
	return bufOut, nil
}

func (e *AeadEngine) Open(NewAEAD func() (cipher.AEAD, error), data []byte) ([]byte, error) {
	e.Logger.Trace("Decrypt AEAD", "datalen", len(data))
	aead, err := NewAEAD()
	if err != nil {
		return nil, err
	}
	nonceSize := aead.NonceSize()
	e.Logger.Trace("Decrypt AEAD", "noncesize", nonceSize)
	if len(data) < nonceSize {
		return nil, errors.New("data is too short")
	}

	nonce, dataEnc := data[:nonceSize], data[nonceSize:]
	bufOut, err := aead.Open(nil, nonce, dataEnc, nil)
	e.Logger.Trace("Decrypt AEAD", "decryptedlen", len(bufOut))
	return bufOut, err
}
