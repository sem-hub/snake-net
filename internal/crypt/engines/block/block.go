package block

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"log/slog"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/crypt/engines"
)

type BlockEngine struct {
	engines.EngineData
	SharedSecret []byte
	logger       *slog.Logger
}

func NewBlockEngine(name string, sharedSecret []byte) *BlockEngine {
	engine := BlockEngine{}
	engine.EngineData = *engines.NewEngineData(name, "block")
	engine.SharedSecret = sharedSecret
	engine.logger = configs.InitLogger("block")
	return &engine
}

func (e *BlockEngine) Encrypt(block cipher.Block, newBlock func(cipher.Block, []byte) cipher.BlockMode, data []byte) ([]byte, error) {
	e.logger.Debug("Encrypt block", "datalen", len(data))

	padding := block.BlockSize() - len(data)%block.BlockSize()
	padData := append(data, bytes.Repeat([]byte{byte(padding)}, padding)...)

	iv := make([]byte, block.BlockSize())
	rand.Read(iv)
	blockCipher := newBlock(block, iv)

	bufOut := make([]byte, len(padData)+len(iv))
	// copy iv to output buf
	copy(bufOut[:block.BlockSize()], iv)

	blockCipher.CryptBlocks(bufOut[block.BlockSize():], padData)
	e.logger.Debug("Encrypt block", "encryptedlen", len(bufOut))
	return bufOut, nil
}

func (e *BlockEngine) Decrypt(block cipher.Block, newBlock func(cipher.Block, []byte) cipher.BlockMode, data []byte) ([]byte, error) {
	e.logger.Debug("Decrypt block", "datalen", len(data))
	if len(data) < block.BlockSize() {
		e.logger.Error("Data too short for this cipher", "datalen", len(data), "blocksize", block.BlockSize())
		return nil, errors.New("data is too short for this block cipher")
	}

	iv := data[:block.BlockSize()]
	blockCipher := newBlock(block, iv)

	bufOut := make([]byte, len(data)-len(iv))

	e.logger.Debug("before Decrypt block", "buflen", len(bufOut))
	blockCipher.CryptBlocks(bufOut, data[block.BlockSize():])
	e.logger.Debug("Decrypt block", "decryptedlen", len(bufOut))

	// Unpad
	padding := int(bufOut[len(bufOut)-1])
	return bufOut[:len(bufOut)-padding], nil
}
