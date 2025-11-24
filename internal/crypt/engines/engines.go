package engines

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
