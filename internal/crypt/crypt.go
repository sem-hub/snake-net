package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"slices"
	"strings"
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
	//configs.GetLogger().Debug("Verify", "msg len", len(msg), "siglen", len(sig))
	return ed25519.Verify(s.SessionPublicKey, msg, sig)
}

func (s *Secrets) Sign(msg []byte) []byte {
	//configs.GetLogger().Debug("Sign", "msglen", len(msg))
	return ed25519.Sign(s.SessionPrivateKey, msg)
}

func (s *Secrets) XOR(data *[]byte) {
	for i := 0; i < len(*data); i++ {
		(*data)[i] ^= s.XORKey[i%len(s.XORKey)]
	}
}

func (s *Secrets) MinimalSize() int {
	return 64
}

func (s *Secrets) EncryptAndSeal(data []byte) ([]byte, error) {
	signature := s.Sign(data)
	buf, err := s.cryptDecrypt(data)
	buf = append(buf, signature...)

	return buf, err
}

func (s *Secrets) DecryptAndVerify(data []byte) ([]byte, error) {
	signatureStart := len(data) - s.MinimalSize()
	buf, err := s.cryptDecrypt(data[:signatureStart])
	if !s.Verify(buf, data[signatureStart:]) {
		return nil, errors.New("verify error")
	}
	return buf, err
}

func (s *Secrets) cryptDecrypt(data []byte) ([]byte, error) {
	buf := slices.Clone(data)
	//configs.GetLogger().Debug("CryptDecrypt", "datalen", len(data), "sharedsecret", hex.EncodeToString(s.SharedSecret))
	bReader := bytes.NewReader(data)
	block, err := aes.NewCipher(s.SharedSecret)
	if err != nil {
		return nil, err
	}
	var iv [aes.BlockSize]byte
	stream := cipher.NewCTR(block, iv[:])

	reader := &cipher.StreamReader{S: stream, R: bReader}
	buf1 := new(strings.Builder)
	if _, err := io.Copy(buf1, reader); err != nil {
		return nil, err
	}
	//configs.GetLogger().Debug("CryptDecrypt", "encryptedlen", len(data))
	copy(buf, []byte(buf1.String()))
	return buf, nil
}
