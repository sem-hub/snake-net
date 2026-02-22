package engines

import (
	"errors"
	"sync"

	"github.com/sem-hub/snake-net/internal/configs"
)

var EnginesList = map[string]string{
	// Universal (block)
	"aes":       "block",
	"speck":     "block",
	"rc6":       "block",
	"threefish": "block",
	// Stream only
	"salsa20":  "stream",
	"chacha20": "stream",
	"rabbit":   "stream",
	"hc":       "stream",
	// AEAD
	"chacha20poly1305": "aead",
	"xsalsa20poly1305": "aead",
	"grain":            "aead",
	"aegis":            "aead",
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
	GetOverhead() int
}
type EngineData struct {
	Name   string
	Type   string
	Logger *configs.ColorLogger
}

func NewEngineData(Name, Type string) *EngineData {
	return &EngineData{
		Name: Name,
		Type: Type,
	}
}

func IsEngineSupported(engine string) bool {
	_, exists := EnginesList[engine]
	return exists
}

func GetEngineType(engine string) string {
	engineType, exists := EnginesList[engine]
	if !exists {
		return ""
	}
	return engineType
}

func IsModeSupported(mode string) bool {
	_, exists := ModesList[mode]
	return exists
}

// Engine factory
type EngineConstructor func(sharedSecret []byte, keySize int, mode string) (CryptoEngine, error)

var (
	engineRegistry      = make(map[string]EngineConstructor)
	engineRegistryMutex sync.RWMutex
)

// RegisterEngine registers an engine constructor under a given name
func RegisterEngine(name string, constructor EngineConstructor) {
	engineRegistryMutex.Lock()
	defer engineRegistryMutex.Unlock()
	engineRegistry[name] = constructor
}

// NewEngineByName creates a new engine instance by name
func NewEngineByName(name string, sharedSecret []byte, keySize int, mode string) (CryptoEngine, error) {
	engineRegistryMutex.RLock()
	constructor, exists := engineRegistry[name]
	engineRegistryMutex.RUnlock()

	if !exists {
		return nil, errors.New("engine " + name + " is not available")
	}

	return constructor(sharedSecret, keySize, mode)
}

// GetAvailableEngines returns a list of all registered engine names
func GetAvailableEngines() []string {
	engineRegistryMutex.RLock()
	defer engineRegistryMutex.RUnlock()

	names := make([]string, 0, len(engineRegistry))
	for name := range engineRegistry {
		names = append(names, name)
	}
	return names
}

// IsEngineAvailable checks if an engine is registered
func IsEngineAvailable(name string) bool {
	engineRegistryMutex.RLock()
	defer engineRegistryMutex.RUnlock()
	_, exists := engineRegistry[name]
	return exists
}
