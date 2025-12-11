package engines

import (
	"log/slog"
	"slices"

	"github.com/sem-hub/snake-net/internal/configs"
)

var EngineList = []string{
	// Universal
	"aes",
	"serpent",
	"camellia",
	"twofish",
	"rc6",
	// Block
	"present",
	"idea",
	"threefish",
	"gost",
	// Stream
	"salsa20",
	"chacha20",
	"rabbit",
	"hc",
	// AEAD
	"chacha20poly1305",
	"xsalsa20poly1305",
	"grain",
}

var ModeList = map[string]string{
	"cbc": "block",
	"ctr": "stream",
	"cfb": "stream",
	"ofb": "stream",
	"gcm": "aead",
	"ccm": "aead",
	"ocb": "aead",
	"eax": "aead",
	"mgm": "aead",
}

type EngineData struct {
	Name   string
	Type   string
	Logger *slog.Logger
}

type CryptoEngine interface {
	Encrypt([]byte) ([]byte, error)
	Decrypt([]byte) ([]byte, error)
	GetName() string
	GetType() string
}

func NewEngineData(Name, Type string) *EngineData {
	return &EngineData{
		Name:   Name,
		Type:   Type,
		Logger: configs.InitLogger(Type + "-" + Name),
	}
}

func IsEngineSupported(engine string) bool {
	return slices.Contains(EngineList, engine)
}

func IsModeSupported(mode string) bool {
	_, exists := ModeList[mode]
	return exists
}
