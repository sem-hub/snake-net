package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"log/slog"

	"github.com/sem-hub/snake-net/internal/configs"
)

const FIRSTSECRET = "pu6apieV6chohghah2MooshepaethuCh"

const SIGNLEN = 64

type Secrets struct {
	logger            *slog.Logger
	SharedSecret      []byte
	SessionPrivateKey ed25519.PrivateKey
	SessionPublicKey  ed25519.PublicKey
}

var logger *slog.Logger

func NewSecrets(secret string) *Secrets {
	s := Secrets{}
	s.logger = configs.InitLogger("crypt")
	logger = s.logger

	s.SharedSecret = make([]byte, 32)
	if secret == "" {
		s.logger.Info("Using default shared secret")
		secret = FIRSTSECRET
	} else {
		s.logger.Info("Using provided shared secret")
	}
	sum256 := sha256.Sum256([]byte(secret))
	copy(s.SharedSecret, sum256[:])

	s.SessionPublicKey, s.SessionPrivateKey, _ =
		ed25519.GenerateKey(bytes.NewReader([]byte(s.SharedSecret)))

	return &s
}

func (s *Secrets) GetPublicKey() *ed25519.PublicKey {
	return &s.SessionPublicKey
}

func (s *Secrets) GetPrivateKey() *ed25519.PrivateKey {
	return &s.SessionPrivateKey
}

func (s *Secrets) GetSharedSecret() []byte {
	return s.SharedSecret
}

func (s *Secrets) Verify(msg []byte, sig []byte) bool {
	s.logger.Debug("Verify", "msg len", len(msg), "siglen", len(sig))
	return ed25519.Verify(s.SessionPublicKey, msg, sig)
}

func (s *Secrets) Sign(msg []byte) []byte {
	s.logger.Debug("Sign", "msglen", len(msg))
	return ed25519.Sign(s.SessionPrivateKey, msg)
}

func (s *Secrets) Encrypt(data []byte) ([]byte, error) {
	return s.CryptDecrypt(data)
}

func (s *Secrets) Decrypt(data []byte) ([]byte, error) {
	return s.CryptDecrypt(data)
}

func (s *Secrets) CryptDecrypt(data []byte) ([]byte, error) {
	s.logger.Debug("CryptDecrypt", "datalen", len(data))
	block, err := aes.NewCipher(s.SharedSecret)
	if err != nil {
		return nil, err
	}
	// XXX generate random IV: rand.Read(iv) for Encryption
	// XXX and copy(iv, data[:aes.BlockSize]) for Decryption
	iv := make([]byte, aes.BlockSize)
	stream := cipher.NewCTR(block, iv)

	bufOut := make([]byte, len(data)) // len(data)+aes.BlockSize
	// copy iv to buf
	// copy(bufOut[:aes.BlockSize], iv)

	stream.XORKeyStream(bufOut, data) // bufOut[aes.BlockSize:]
	s.logger.Debug("CryptDecrypt", "encryptedlen", len(bufOut))
	return bufOut, nil
}
