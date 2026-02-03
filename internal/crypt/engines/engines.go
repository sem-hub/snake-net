package engines

import (
	"log/slog"
	"slices"
)

var EnginesList = []string{
	// Universal (block)
	"aes",
	"speck",
	"rc6",
	"threefish",
	// Stream only
	"salsa20",
	"chacha20",
	"rabbit",
	"hc",
	// AEAD
	"chacha20poly1305",
	"xsalsa20poly1305",
	"grain",
	"aegis",
}

var ModesList = map[string]string{
	"cbc": "block",
	"ctr": "stream",
	"gcm": "aead",
	"ccm": "aead",
	"ocb": "aead",
	"eax": "aead",
}

type CryptoEngine interface {
	Encrypt([]byte) ([]byte, error)
	Decrypt([]byte) ([]byte, error)
	GetName() string
	GetType() string
	GetKeySizes() []int
}
type EngineData struct {
	Name   string
	Type   string
	Logger *slog.Logger
}

func NewEngineData(Name, Type string) *EngineData {
	return &EngineData{
		Name: Name,
		Type: Type,
	}
}

func IsEngineSupported(engine string) bool {
	return slices.Contains(EnginesList, engine)
}

func IsModeSupported(mode string) bool {
	_, exists := ModesList[mode]
	return exists
}
