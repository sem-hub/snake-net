package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"strings"

	"github.com/sem-hub/snake-net/internal/configs"
)

const FIRSTSECRET = "pu6apieV6chohghah2MooshepaethuCh"

const SIGNLEN = 64

const XORKEYLEN = 32

type Secrets struct {
	SharedSecret      []byte
	SessionPrivateKey ed25519.PrivateKey
	SessionPublicKey  ed25519.PublicKey
	XORKey            []byte
}

func NewSecrets() *Secrets {
	s := Secrets{}

	s.SharedSecret = make([]byte, 32)
	copy(s.SharedSecret, []byte(FIRSTSECRET))
	s.SessionPublicKey, s.SessionPrivateKey, _ =
		ed25519.GenerateKey(bytes.NewReader([]byte(s.SharedSecret)))

	s.XORKey = make([]byte, XORKEYLEN)
	rand.Read(s.XORKey)

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
	return ed25519.Verify(s.SessionPublicKey, msg, sig)
}

func (s *Secrets) Sign(msg []byte) []byte {
	return ed25519.Sign(s.SessionPrivateKey, msg)
}

func (s *Secrets) XOR(data *[]byte) {
	for i := 0; i < len(*data); i++ {
		(*data)[i] ^= s.XORKey[i%len(s.XORKey)]
	}
}

func (s *Secrets) CryptDecrypt(data []byte) ([]byte, error) {
	configs.GetLogger().Debug("CryptDecrypt", "data len", len(data))
	bReader := bytes.NewReader(data)
	block, err := aes.NewCipher(s.SharedSecret)
	if err != nil {
		return nil, err
	}
	var iv [aes.BlockSize]byte
	stream := cipher.NewOFB(block, iv[:])

	reader := &cipher.StreamReader{S: stream, R: bReader}
	buf := new(strings.Builder)
	if _, err := io.Copy(buf, reader); err != nil {
		return nil, err
	}
	data = []byte(buf.String())
	return data, nil
}
