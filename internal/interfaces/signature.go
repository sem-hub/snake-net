package interfaces

import "crypto/ed25519"

type SignatureInterface interface {
	Sign(msg []byte) []byte
	Verify(msg []byte, sig []byte) bool
	SignLen() int
	GetName() string
}

type SecretsInterface interface {
	GetPrivateKey() *ed25519.PrivateKey
	GetPublicKey() *ed25519.PublicKey
	GetSharedSecret() []byte
}
