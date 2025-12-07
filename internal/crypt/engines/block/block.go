package block

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"errors"

	"github.com/sem-hub/snake-net/internal/crypt/engines"
)

type BlockEngine struct {
	engines.EngineData
}

func NewBlockEngine(name string) *BlockEngine {
	engine := BlockEngine{}
	engine.EngineData = *engines.NewEngineData(name, "block")

	return &engine
}

func (e *BlockEngine) BlockEncrypt(NewCipher func() (cipher.Block, error), data []byte) ([]byte, error) {
	e.Logger.Debug("BlockEncrypt", "datalen", len(data))

	block, err := NewCipher()
	if err != nil {
		return nil, err
	}

	padding := block.BlockSize() - len(data)%block.BlockSize()
	padData := append(data, bytes.Repeat([]byte{byte(padding)}, padding)...)

	iv := make([]byte, block.BlockSize())
	rand.Read(iv)
	blockCipher := cipher.NewCBCEncrypter(block, iv)

	bufOut := make([]byte, len(padData)+len(iv))
	// copy iv to output buf
	copy(bufOut[:block.BlockSize()], iv)

	blockCipher.CryptBlocks(bufOut[block.BlockSize():], padData)
	e.Logger.Debug("BlockEncrypt", "encryptedlen", len(bufOut))
	return bufOut, nil
}

func (e *BlockEngine) BlockDecrypt(NewCipher func() (cipher.Block, error), data []byte) ([]byte, error) {
	e.Logger.Debug("BlockDecrypt", "datalen", len(data))

	block, err := NewCipher()
	if err != nil {
		return nil, err
	}

	if len(data) < block.BlockSize() {
		e.Logger.Error("Data too short for this cipher", "datalen", len(data), "blocksize", block.BlockSize())
		return nil, errors.New("data is too short for this block cipher")
	}

	iv := data[:block.BlockSize()]
	blockCipher := cipher.NewCBCDecrypter(block, iv)

	bufOut := make([]byte, len(data)-len(iv))

	e.Logger.Debug("before BlockDecrypt", "buflen", len(bufOut))
	blockCipher.CryptBlocks(bufOut, data[block.BlockSize():])
	e.Logger.Debug("BlockDecrypt", "decryptedlen", len(bufOut))

	// Unpad
	padding := int(bufOut[len(bufOut)-1])
	if padding >= len(bufOut) {
		e.Logger.Error("Invalid padding", "padding", padding, "buflen", len(bufOut))
		return nil, errors.New("invalid padding")
	}
	return bufOut[:len(bufOut)-padding], nil
}
