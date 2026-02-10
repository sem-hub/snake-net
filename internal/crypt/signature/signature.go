package signature

import (
	"crypto/ed25519"
	"errors"
	"slices"
	"sync"

	"github.com/sem-hub/snake-net/internal/configs"
)

var SignatureList = []string{
	"hmac-sha256",
	"hmac-blake2b",
	"ed25519",
	"poly1305",
}

type SignatureInterface interface {
	GetName() string
	SignLen() int
	Verify(msg []byte, sig []byte) bool
	Sign(msg []byte) []byte
	SetSharedSecret(secret []byte)
	SetPublicKey(pub ed25519.PublicKey)
	SetPrivateKey(priv ed25519.PrivateKey)
	GetPrivateKey() *ed25519.PrivateKey
	GetPublicKey() *ed25519.PublicKey
}

type Signature struct {
	SignatureInterface
	name              string
	Logger            *configs.ColorLogger
	sessionPrivateKey ed25519.PrivateKey
	sessionPublicKey  ed25519.PublicKey
	sharedSecret      []byte
}

func NewSignature(secret []byte, name string) *Signature {
	sig := &Signature{
		sharedSecret: secret,
		name:         name,
	}

	sig.Logger = configs.InitLogger("crypto")
	return sig
}

func (s *Signature) SetSharedSecret(secret []byte) {
	s.sharedSecret = secret
}

func (s *Signature) SetPublicKey(pub ed25519.PublicKey) {
	s.sessionPublicKey = pub
}

func (s *Signature) SetPrivateKey(priv ed25519.PrivateKey) {
	s.sessionPrivateKey = priv
}

func (s *Signature) GetPrivateKey() *ed25519.PrivateKey {
	return &s.sessionPrivateKey
}

func (s *Signature) GetPublicKey() *ed25519.PublicKey {
	return &s.sessionPublicKey
}

func IsEngineSupported(engine string) bool {
	return slices.Contains(SignatureList, engine)
}

// Signature engine factory
type SignatureConstructor func(sharedSecret []byte) SignatureInterface

var (
	signatureRegistry = make(map[string]SignatureConstructor)
	signatureRegistryMutex sync.RWMutex
)

// RegisterSignatureEngine registers a signature engine constructor
func RegisterSignatureEngine(name string, constructor SignatureConstructor) {
	signatureRegistryMutex.Lock()
	defer signatureRegistryMutex.Unlock()
	signatureRegistry[name] = constructor
}

// NewSignatureEngineByName creates a new signature engine by name
func NewSignatureEngineByName(name string, sharedSecret []byte) (SignatureInterface, error) {
	signatureRegistryMutex.RLock()
	constructor, exists := signatureRegistry[name]
	signatureRegistryMutex.RUnlock()

	if !exists {
		return nil, errors.New("signature engine " + name + " is not available")
	}

	return constructor(sharedSecret), nil
}

// GetAvailableSignatureEngines returns all registered signature engines
func GetAvailableSignatureEngines() []string {
	signatureRegistryMutex.RLock()
	defer signatureRegistryMutex.RUnlock()

	names := make([]string, 0, len(signatureRegistry))
	for name := range signatureRegistry {
		names = append(names, name)
	}
	return names
}

// IsSignatureEngineAvailable checks if a signature engine is registered
func IsSignatureEngineAvailable(name string) bool {
	signatureRegistryMutex.RLock()
	defer signatureRegistryMutex.RUnlock()
	_, exists := signatureRegistry[name]
	return exists
}
