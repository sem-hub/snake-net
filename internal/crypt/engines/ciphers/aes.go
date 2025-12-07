package ciphers

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"

	"github.com/sem-hub/snake-net/internal/crypt/engines"
	"github.com/sem-hub/snake-net/internal/crypt/engines/aead"
	"github.com/sem-hub/snake-net/internal/crypt/engines/block"
	"github.com/sem-hub/snake-net/internal/crypt/engines/stream"
	"github.com/starainrt/go-crypto/ocb"
	ccm "gitlab.com/go-extension/aes-ccm"
)

type AesEngine struct {
	engines.EngineData
	block.BlockEngine
	stream.StreamEngine
	aead.AeadEngine
	SharedSecret []byte
	Mode         string
}

func NewAesEngine(sharedSecret []byte, size int, mode string) (*AesEngine, error) {
	allowedKeySizes := []int{128, 192, 256}
	if size == 0 {
		size = 256
	}

	found := false
	for _, s := range allowedKeySizes {
		if size == s {
			found = true
			break
		}
	}

	if !found {
		return nil, errors.New("invalid key size")
	}
	keySize := size / 8

	if !engines.IsModeSupported(mode) {
		return nil, errors.New("unsupported mode")
	}

	engine := AesEngine{}
	if mode == "ccm" || mode == "gcm" || mode == "ocb" {
		engine.AeadEngine = *aead.NewAeadEngine("aes-" + mode)
		engine.EngineData = engine.AeadEngine.EngineData
	}
	if mode == "cbc" {
		engine.BlockEngine = *block.NewBlockEngine("aes-" + mode)
		engine.EngineData = engine.BlockEngine.EngineData
	}
	if mode == "ctr" {
		engine.StreamEngine = *stream.NewStreamEngine("aes-" + mode)
		engine.EngineData = engine.StreamEngine.EngineData
	}
	engine.Mode = mode
	engine.SharedSecret = sharedSecret[:keySize]
	return &engine, nil
}

func (e *AesEngine) GetName() string {
	return e.EngineData.Name
}

func (e *AesEngine) GetType() string {
	return e.EngineData.Type
}

func (e *AesEngine) NewCipher() (cipher.Block, error) {
	if e.Mode == "cbc" {
		return aes.NewCipher(e.SharedSecret)
	}
	return nil, errors.New("unsupported mode")
}

func (e *AesEngine) NewStream(iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(e.SharedSecret)
	if err != nil {
		return nil, err
	}
	if e.Mode == "ctr" {
		return cipher.NewCTR(block, iv), nil
	}
	if e.Mode == "ofb" {
		return cipher.NewOFB(block, iv), nil
	}
	return nil, errors.New("unsupported mode")
}

func (e *AesEngine) NewAEAD() (cipher.AEAD, error) {
	block, err := aes.NewCipher(e.SharedSecret)
	if err != nil {
		return nil, err
	}
	if e.Mode == "ccm" {
		return ccm.NewCCM(block)
	}
	if e.Mode == "gcm" {
		return cipher.NewGCM(block)
	}
	if e.Mode == "ocb" {
		return ocb.NewOCB(block)
	}
	return nil, errors.New("unsupported mode")
}

func (e *AesEngine) Encrypt(data []byte) ([]byte, error) {
	e.Logger.Debug("Encrypt", "datalen", len(data))
	if e.Mode == "cbc" {
		return e.BlockEngine.BlockEncrypt(e.NewCipher, data)
	}
	if e.Mode == "ccm" || e.Mode == "gcm" || e.Mode == "ocb" {
		return e.AeadEngine.Seal(e.NewAEAD, data)
	}
	if e.Mode == "ctr" {
		return e.StreamEngine.StreamEncrypt(aes.BlockSize, e.NewStream, data)
	}
	return nil, errors.New("unsupported mode")
}

func (e *AesEngine) Decrypt(data []byte) ([]byte, error) {
	e.Logger.Debug("Decrypt", "datalen", len(data))
	if e.Mode == "cbc" {
		return e.BlockEngine.BlockDecrypt(e.NewCipher, data)
	}
	if e.Mode == "ccm" || e.Mode == "gcm" || e.Mode == "ocb" {
		return e.AeadEngine.Open(e.NewAEAD, data)
	}
	if e.Mode == "ctr" {
		return e.StreamEngine.StreamDecrypt(aes.BlockSize, e.NewStream, data)
	}
	return nil, errors.New("unsupported mode")
}
