package stream

import (
	"crypto/cipher"

	"golang.org/x/crypto/chacha20"
)

type Chacha20Engine struct {
	StreamEngine
	SharedSecret []byte
}

func NewChacha20Engine(sharedSecret []byte) (*Chacha20Engine, error) {
	engine := Chacha20Engine{}
	engine.StreamEngine = *NewStreamEngine("chacha20")
	engine.SharedSecret = sharedSecret
	return &engine, nil
}

func (e *Chacha20Engine) GetName() string {
	return e.EngineData.Name
}

func (e *Chacha20Engine) GetType() string {
	return e.EngineData.Type
}

func (e *Chacha20Engine) NewCipher(nonce []byte) (cipher.Stream, error) {
	return chacha20.NewUnauthenticatedCipher(e.SharedSecret, nonce)
}

func (e *Chacha20Engine) Encrypt(data []byte) ([]byte, error) {
	e.Logger.Debug("Encrypt", "datalen", len(data))
	return e.StreamEngine.StreamEncrypt(chacha20.NonceSize, e.NewCipher, data)
}

func (e *Chacha20Engine) Decrypt(data []byte) ([]byte, error) {
	e.Logger.Debug("Decrypt", "datalen", len(data))
	return e.StreamEngine.StreamDecrypt(chacha20.NonceSize, e.NewCipher, data)

}
