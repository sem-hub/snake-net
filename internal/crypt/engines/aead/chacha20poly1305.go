package aead

import (
	"crypto/cipher"
	"log/slog"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/sem-hub/snake-net/internal/configs"
)

type Chacha20Poly1305Engine struct {
	AeadEngine
	logger *slog.Logger
}

func NewChacha20Poly1305Engine(sharedSecret []byte) (*Chacha20Poly1305Engine, error) {
	engine := Chacha20Poly1305Engine{}
	engine.AeadEngine = *NewAeadEngine("chacha20poly1305")
	engine.SharedSecret = sharedSecret
	engine.logger = configs.InitLogger("chacha20poly1305")
	return &engine, nil
}

func (e *Chacha20Poly1305Engine) GetName() string {
	return e.EngineData.Name
}

func (e *Chacha20Poly1305Engine) GetType() string {
	return e.EngineData.Type
}

func (e *Chacha20Poly1305Engine) NewAEAD() (cipher.AEAD, error) {
	return chacha20poly1305.New(e.SharedSecret)
}

func (e *Chacha20Poly1305Engine) Encrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Seal", "datalen", len(data))
	return e.AeadEngine.Seal(e.NewAEAD, data)
}

func (e *Chacha20Poly1305Engine) Decrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Open", "datalen", len(data))
	return e.AeadEngine.Open(e.NewAEAD, data)
}
