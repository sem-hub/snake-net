package block

import (
	"crypto/cipher"

	"github.com/rmuch/gost"
)

// GOST28147-89 block cipher engine
type GostEngine struct {
	BlockEngine
	SharedSecret []byte
}

// Only 256 bits key size
func NewGostEngine(sharedSecret []byte) (*GostEngine, error) {
	engine := GostEngine{}
	engine.BlockEngine = *NewBlockEngine("gost")
	engine.SharedSecret = sharedSecret
	return &engine, nil
}

func (e *GostEngine) GetName() string {
	return e.BlockEngine.Name
}

func (e *GostEngine) GetType() string {
	return e.BlockEngine.Type
}

func (e *GostEngine) NewCipher() (cipher.Block, error) {
	return gost.NewBlockCipher(e.SharedSecret, gost.SboxIdtc26gost28147paramZ)
}

func (e *GostEngine) Encrypt(data []byte) ([]byte, error) {
	e.Logger.Debug("Encrypt", "datalen", len(data))
	return e.BlockEngine.BlockEncrypt(e.NewCipher, data)
}

func (e *GostEngine) Decrypt(data []byte) ([]byte, error) {
	e.Logger.Debug("Decrypt", "datalen", len(data))
	return e.BlockEngine.BlockDecrypt(e.NewCipher, data)
}
