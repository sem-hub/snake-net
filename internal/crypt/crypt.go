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
	//lint:ignore ST1001 reason: it's safer to use . import here to avoid name conflicts
	. "github.com/sem-hub/snake-net/internal/interfaces"
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
	logger = configs.InitLogger("crypt")
	s.logger = logger

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

func SignLen() int {
	return SIGNLEN
}

func (s *Secrets) DecryptAndVerify(msg []byte, n int, flags Cmd) ([]byte, error) {
	buf := make([]byte, 0)
	signLen := 0
	var signature []byte
	// Save signature
	if (flags & NoSignature) == 0 {
		signLen = SignLen()
		signature = msg[n-signLen : n]
	}
	// decrypt and verify the packet or just verify if NoEncryptionCmd flag set
	if (flags & NoEncryption) == 0 {
		s.logger.Debug("Decrypting")
		data, err := s.Decrypt(msg[:n-signLen])
		if err != nil {
			s.logger.Error("DecryptAndVerify error", "error", err)
			return nil, err
		}
		s.logger.Debug("After decryption", "datalen", len(data), "msglen", len(msg))
		buf = append(buf, data...)
	} else {
		buf = append(buf, msg[:n-signLen]...)
	}
	if (flags & NoSignature) == 0 {
		if !s.Verify(buf[:n-signLen], signature) {
			s.logger.Error("DecryptAndVerify: verify error")
			return nil, errors.New("verify error")
		}
		s.logger.Debug("Signature verified")
	}
	return buf, nil
}

func (s *Secrets) SignAndEncrypt(msg []byte, cmd Cmd) ([]byte, error) {
	buf := make([]byte, 0)
	if (cmd & NoEncryption) == 0 {
		s.logger.Debug("client Write encrypting", "len", len(msg))
		data, err := s.Encrypt(msg)
		if err != nil {
			return nil, err
		}
		buf = append(buf, data...)
	} else {
		buf = append(buf, msg...)
	}

	// Sign BEFORE encryption
	// Unencrypted signature at the end
	if (cmd & NoSignature) == 0 {
		s.logger.Debug("client Write signing")
		signature := s.Sign(msg)
		buf = append(buf, signature...)
	}
	s.logger.Debug("client Write SignAndEncrypt done", "len", len(buf))
	return buf, nil
}
