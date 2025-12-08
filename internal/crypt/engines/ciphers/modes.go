package ciphers

import (
	"crypto/cipher"
	"errors"

	"github.com/sem-hub/snake-net/internal/crypt/engines"
	"github.com/sem-hub/snake-net/internal/crypt/engines/aead"
	"github.com/sem-hub/snake-net/internal/crypt/engines/block"
	"github.com/sem-hub/snake-net/internal/crypt/engines/stream"
	"github.com/starainrt/go-crypto/ocb"
	ccm "gitlab.com/go-extension/aes-ccm"
)

type Modes struct {
	engines.EngineData
	block.BlockEngine
	stream.StreamEngine
	aead.AeadEngine
	SharedSecret []byte
	Mode         string
	NewCipher    func() (cipher.Block, error)
	BlockSize    func() int
}

func NewModes(name, mode string, size int, allowedKeySizes []int, sharedSecret []byte,
	newCipherFunc func() (cipher.Block, error), blockSizeFunc func() int) (*Modes, error) {
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

	engine := Modes{}
	if mode == "ccm" || mode == "gcm" || mode == "ocb" {
		engine.AeadEngine = *aead.NewAeadEngine(name + "-" + mode)
		engine.EngineData = engine.AeadEngine.EngineData
	}
	if mode == "cbc" {
		engine.BlockEngine = *block.NewBlockEngine(name + "-" + mode)
		engine.EngineData = engine.BlockEngine.EngineData
	}
	if mode == "ctr" {
		engine.StreamEngine = *stream.NewStreamEngine(name + "-" + mode)
		engine.EngineData = engine.StreamEngine.EngineData
	}
	engine.Mode = mode
	engine.SharedSecret = sharedSecret[:keySize]
	engine.NewCipher = newCipherFunc
	engine.BlockSize = blockSizeFunc
	return &engine, nil
}

func (e *Modes) GetName() string {
	return e.EngineData.Name
}

func (e *Modes) GetType() string {
	return e.EngineData.Type
}

func (e *Modes) NewStream(iv []byte) (cipher.Stream, error) {
	block, err := e.NewCipher()
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

func (e *Modes) NewAEAD() (cipher.AEAD, error) {
	block, err := e.NewCipher()
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

func (e *Modes) Encrypt(data []byte) ([]byte, error) {
	e.Logger.Debug("Encrypt", "datalen", len(data))
	if e.Mode == "cbc" {
		return e.BlockEngine.BlockEncrypt(e.NewCipher, data)
	}
	if e.Mode == "ccm" || e.Mode == "gcm" || e.Mode == "ocb" {
		return e.AeadEngine.Seal(e.NewAEAD, data)
	}
	if e.Mode == "ctr" {
		return e.StreamEngine.StreamEncrypt(e.BlockSize(), e.NewStream, data)
	}
	return nil, errors.New("unsupported mode")
}

func (e *Modes) Decrypt(data []byte) ([]byte, error) {
	e.Logger.Debug("Decrypt", "datalen", len(data))
	if e.Mode == "cbc" {
		return e.BlockEngine.BlockDecrypt(e.NewCipher, data)
	}
	if e.Mode == "ccm" || e.Mode == "gcm" || e.Mode == "ocb" {
		return e.AeadEngine.Open(e.NewAEAD, data)
	}
	if e.Mode == "ctr" {
		return e.StreamEngine.StreamDecrypt(e.BlockSize(), e.NewStream, data)
	}
	return nil, errors.New("unsupported mode")
}
