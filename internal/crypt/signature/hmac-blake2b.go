package signature

import (
	"crypto/hmac"
	"golang.org/x/crypto/blake2b"
	"log/slog"

	"github.com/sem-hub/snake-net/internal/configs"
)

type SignatureHMACBlake struct {
	Signature
	logger *slog.Logger
}

func NewSignatureHMACBlake(secret []byte) *SignatureHMACBlake {
	sig := &SignatureHMACBlake{
		Signature: *NewSignature(secret),
	}
	sig.name = "hmac-blake2b"
	sig.logger = configs.InitLogger("signature-hmac-blake2b")
	return sig
}

func (s *SignatureHMACBlake) GetName() string {
	return s.name
}

func (s *SignatureHMACBlake) SignLen() int {
	return 32
}

func (s *SignatureHMACBlake) Verify(msg []byte, sig []byte) bool {
	s.logger.Debug("Verify", "msg len", len(msg), "siglen", len(sig))
	hash, err := blake2b.New256(s.sharedSecret)
	if err != nil {
		s.logger.Error("blake2b.New256 error", "error", err)
		return false
	}
	hash.Write(msg)
	expectedMAC := hash.Sum(nil)
	return hmac.Equal(sig, expectedMAC)
}

func (s *SignatureHMACBlake) Sign(msg []byte) []byte {
	s.logger.Debug("Sign", "msglen", len(msg))
	hash, err := blake2b.New256(s.sharedSecret)
	if err != nil {
		s.logger.Error("blake2b.New256 error", "error", err)
		return nil
	}
	hash.Write(msg)
	return hash.Sum(nil)
}
