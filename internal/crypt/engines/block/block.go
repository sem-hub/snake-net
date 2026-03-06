package block

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"errors"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/crypt/engines"
)

type BlockEngine struct {
	engines.EngineData
	block     cipher.Block
	blockSize int
}

func NewBlockEngine(name string, block cipher.Block) *BlockEngine {
	engine := BlockEngine{}
	engine.EngineData = *engines.NewEngineData(name, "block")
	engine.Logger = configs.GetLogger("crypt")

	engine.block = block
	engine.blockSize = engine.block.BlockSize()

	return &engine
}

func (e *BlockEngine) BlockEncrypt(data []byte) ([]byte, error) {
	e.Logger.Trace("BlockEncrypt", "datalen", len(data))

	padding := e.blockSize - len(data)%e.blockSize
	padData := append(data, bytes.Repeat([]byte{byte(padding)}, padding)...)

	iv := make([]byte, e.blockSize)
	_, _ = rand.Read(iv)
	blockCipher := cipher.NewCBCEncrypter(e.block, iv)

	bufOut := make([]byte, len(padData)+len(iv))
	// copy iv to output buf
	copy(bufOut[:e.blockSize], iv)

	blockCipher.CryptBlocks(bufOut[e.blockSize:], padData)
	e.Logger.Trace("BlockEncrypt", "encryptedlen", len(bufOut))
	return bufOut, nil
}

func (e *BlockEngine) BlockDecrypt(data []byte) ([]byte, error) {
	e.Logger.Trace("BlockDecrypt", "datalen", len(data))

	if len(data) < e.blockSize {
		e.Logger.Error("Data too short for this cipher", "datalen", len(data), "blocksize", e.blockSize)
		return nil, errors.New("data is too short for this block cipher")
	}

	iv := data[:e.blockSize]
	blockCipher := cipher.NewCBCDecrypter(e.block, iv)

	bufOut := make([]byte, len(data)-len(iv))

	e.Logger.Trace("before BlockDecrypt", "buflen", len(bufOut))
	blockCipher.CryptBlocks(bufOut, data[e.blockSize:])
	e.Logger.Trace("BlockDecrypt", "decryptedlen", len(bufOut))

	// Unpad
	padding := int(bufOut[len(bufOut)-1])
	if padding >= len(bufOut) {
		e.Logger.Error("Invalid padding", "padding", padding, "buflen", len(bufOut))
		return nil, errors.New("invalid padding")
	}
	return bufOut[:len(bufOut)-padding], nil
}

func (e *BlockEngine) GetOverhead() int {
	return e.blockSize * 2 // IV size + padding overhead (worst case)
}
