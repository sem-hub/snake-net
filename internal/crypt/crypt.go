package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
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

func NewSecrets(secret []byte) *Secrets {
	s := Secrets{}
	s.logger = configs.InitLogger("crypt")

	s.SharedSecret = make([]byte, 32)
	if len(secret) == 0 {
		s.logger.Info("Using default shared secret")
		sum256 := sha256.Sum256([]byte(FIRSTSECRET))
		copy(s.SharedSecret, sum256[:])
	} else {
		s.logger.Info("Using provided shared secret")
		sum256 := sha256.Sum256([]byte(secret))
		copy(s.SharedSecret, sum256[:])
	}

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
	if s.SharedSecret != nil {
		return s.SharedSecret
	} else {
		return nil
	}
}

func (s *Secrets) Verify(msg []byte, sig []byte) bool {
	s.logger.Debug("Verify", "msg len", len(msg), "siglen", len(sig))
	return ed25519.Verify(s.SessionPublicKey, msg, sig)
}

func (s *Secrets) Sign(msg []byte) []byte {
	s.logger.Debug("Sign", "msglen", len(msg))
	return ed25519.Sign(s.SessionPrivateKey, msg)
}

func (s *Secrets) EncryptAndSeal(data []byte) ([]byte, error) {
	signature := s.Sign(data)
	buf, err := s.CryptDecrypt(data)
	buf = append(buf, signature...)

	return buf, err
}

func (s *Secrets) DecryptAndVerify(data []byte) ([]byte, error) {
	signatureStart := len(data) - SIGNLEN
	buf, err := s.CryptDecrypt(data[:signatureStart])
	if !s.Verify(buf, data[signatureStart:]) {
		return nil, errors.New("verify error")
	}
	return buf, err
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
