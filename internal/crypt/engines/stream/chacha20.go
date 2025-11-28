package stream

import (
	"crypto/rand"
	"log/slog"

	"golang.org/x/crypto/chacha20"

	"github.com/sem-hub/snake-net/internal/configs"
)

type Chacha20Engine struct {
	StreamEngine
	logger *slog.Logger
}

func NewChacha20Engine(sharedSecret []byte) *Chacha20Engine {
	engine := Chacha20Engine{}
	engine.StreamEngine = *NewStreamEngine("chacha20", sharedSecret)
	engine.SharedSecret = sharedSecret
	engine.logger = configs.InitLogger("chacha20")
	return &engine
}

func (e *Chacha20Engine) GetName() string {
	return e.EngineData.Name
}

func (e *Chacha20Engine) GetType() string {
	return e.EngineData.Type
}

func (e *Chacha20Engine) NewCipher(secret, nonce []byte) (*chacha20.Cipher, error) {
	return chacha20.NewUnauthenticatedCipher(secret, nonce)
}

func (e *Chacha20Engine) Encrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Encrypt", "datalen", len(data))
	nonce := make([]byte, chacha20.NonceSize)
	rand.Read(nonce)
	cipher, err := e.NewCipher(e.SharedSecret, nonce)
	if err != nil {
		return nil, err
	}
	bufOut := make([]byte, len(nonce)+len(data))
	// copy nonce to output buf
	copy(bufOut[:chacha20.NonceSize], nonce)

	cipher.XORKeyStream(bufOut[chacha20.NonceSize:], data)
	e.logger.Debug("Encrypt", "encryptedlen", len(bufOut))
	return bufOut, nil
}

func (e *Chacha20Engine) Decrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Decrypt", "datalen", len(data))
	nonce := make([]byte, chacha20.NonceSize)
	copy(nonce, data[:chacha20.NonceSize])
	cipher, err := e.NewCipher(e.SharedSecret, nonce)
	if err != nil {
		return nil, err
	}
	bufOut := make([]byte, len(data)-chacha20.NonceSize)
	cipher.XORKeyStream(bufOut, data[chacha20.NonceSize:])
	e.logger.Debug("Decrypt", "decryptedlen", len(bufOut))
	return bufOut, nil
}
