package engines

import "slices"

var EngineList = []string{
	// AES
	"aes",
	// Block
	"present",
	"idea",
	"twofish",
	"threefish",
	"rc6",
	"serpent",
	"camellia",
	"gost",
	// Stream
	"salsa20",
	"chacha20",
	"rabbit",
	// AEAD
	"chacha20poly1305",
	"xsalsa20poly1305",
}

var ModeList = []string{
	"cbc",
	"ctr",
	"cfb",
	"ofb",
	"gcm",
	"ccm",
	"ocb",
}

type EngineData struct {
	Name string
	Type string
}

type CryptoEngine interface {
	Encrypt([]byte) ([]byte, error)
	Decrypt([]byte) ([]byte, error)
	GetName() string
	GetType() string
}

func NewEngineData(Name, Type string) *EngineData {
	return &EngineData{
		Name: Name,
		Type: Type,
	}
}

func IsEngineSupported(engine string) bool {
	return slices.Contains(EngineList, engine)
}

func IsModeSupported(mode string) bool {
	return slices.Contains(ModeList, mode)
}
