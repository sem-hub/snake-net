package engines

var EngineList = [18]string{
	// Block
	"aes-cbc",
	"present",
	"idea",
	"twofish",
	"threefish",
	"rc6",
	"serpent",
	"camellia",
	"gost",
	// Stream
	"aes-ctr",
	"salsa20",
	"chacha20",
	"rabbit",
	// AEAD
	"aes-gcm",
	"aes-ccm",
	"aes-ocb",
	"chacha20poly1305",
	"xsalsa20poly1305",
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
