package ciphers

import (
	"crypto/cipher"
	"errors"
	"strconv"
	"strings"

	"github.com/ProtonMail/go-crypto/ocb"
	"github.com/sem-hub/eax-mode/eax"
	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/crypt/engines"
	"github.com/sem-hub/snake-net/internal/crypt/engines/aead"
	"github.com/sem-hub/snake-net/internal/crypt/engines/block"
	"github.com/sem-hub/snake-net/internal/crypt/engines/stream"
	ccm "gitlab.com/go-extension/aes-ccm"
)

type Modes struct {
	engines.EngineData
	block.BlockEngine
	stream.StreamEngine
	aead.AeadEngine
	block           cipher.Block
	Mode            string
	allowedKeySizes []int
	KeySize         int
	logger          *configs.ColorLogger
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
	if len(sharedSecret) < keySize {
		return nil, errors.New("shared secret is too short")
	}

	if !engines.IsModeSupported(mode) {
		return nil, errors.New("unsupported mode: " + mode)
	}

	engine := Modes{}
	engine.Mode = mode
	engine.allowedKeySizes = allowedKeySizes
	engine.KeySize = size
	engine.logger = configs.GetLogger("crypt")
	var err error
	engine.block, err = newCipherFunc()
	if err != nil {
		return nil, err
	}
	if engines.ModesList[mode] == "aead" {
		aeadEngine, err := engine.NewAEAD(engine.block)
		if err != nil {
			return nil, err
		}
		engine.AeadEngine = *aead.NewAeadEngine(name+"-"+mode, aeadEngine)
		engine.EngineData = engine.AeadEngine.EngineData
	}
	if engines.ModesList[mode] == "block" {
		engine.BlockEngine = *block.NewBlockEngine(name+"-"+mode, engine.block)
		engine.EngineData = engine.BlockEngine.EngineData
	}
	if engines.ModesList[mode] == "stream" {
		engine.StreamEngine = *stream.NewStreamEngine(name+"-"+mode, engine.block.BlockSize())
		engine.EngineData = engine.StreamEngine.EngineData
	}
	engine.Mode = mode
	return &engine, nil
}

func (e *Modes) GetKeySizes() []int {
	return e.allowedKeySizes
}

func (e *Modes) GetName() string {
	name := e.EngineData.Name
	idx := strings.Index(name, "-")
	name = name[:idx] + "-" + strconv.Itoa(e.KeySize) + name[idx:]
	return name
}

func (e *Modes) GetType() string {
	return e.EngineData.Type
}

func (e *Modes) NewStream(iv []byte) (cipher.Stream, error) {
	if e.Mode == "ctr" {
		return cipher.NewCTR(e.block, iv), nil
	}
	return nil, errors.New("unsupported mode: " + e.Mode)
}

func (e *Modes) NewAEAD(block cipher.Block) (cipher.AEAD, error) {
	if e.Mode == "ccm" {
		return ccm.NewCCM(block)
	}
	if e.Mode == "gcm" {
		return cipher.NewGCM(block)
	}
	if e.Mode == "ocb" {
		return ocb.NewOCB(block)
	}
	if e.Mode == "eax" {
		if block.BlockSize() < 16 {
			defaultNonceSize := 16
			return eax.NewEAXWithNonceAndTagSize(block, defaultNonceSize, block.BlockSize())
		}
		return eax.NewEAX(block)
	}
	return nil, errors.New("unsupported mode: " + e.Mode)
}

func (e *Modes) Encrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Encrypt", "datalen", len(data))
	if engines.ModesList[e.Mode] == "block" {
		return e.BlockEngine.BlockEncrypt(data)
	}
	if engines.ModesList[e.Mode] == "aead" {
		return e.AeadEngine.Seal(data)
	}
	if engines.ModesList[e.Mode] == "stream" {
		return e.StreamEngine.StreamEncrypt(e.NewStream, data)
	}
	return nil, errors.New("unsupported mode: " + e.Mode)
}

func (e *Modes) Decrypt(data []byte) ([]byte, error) {
	e.logger.Debug("Decrypt", "datalen", len(data))
	if engines.ModesList[e.Mode] == "block" {
		return e.BlockEngine.BlockDecrypt(data)
	}
	if engines.ModesList[e.Mode] == "aead" {
		return e.AeadEngine.Open(data)
	}
	if engines.ModesList[e.Mode] == "stream" {
		return e.StreamEngine.StreamDecrypt(e.NewStream, data)
	}
	return nil, errors.New("unsupported mode: " + e.Mode)
}

func (e *Modes) GetOverhead() int {
	if engines.ModesList[e.Mode] == "block" {
		return e.BlockEngine.GetOverhead()
	}
	if engines.ModesList[e.Mode] == "aead" {
		return e.AeadEngine.GetOverhead()
	}
	if engines.ModesList[e.Mode] == "stream" {
		return e.StreamEngine.GetOverhead()
	}
	return 0
}
