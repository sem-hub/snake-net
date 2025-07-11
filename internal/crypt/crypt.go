package crypt

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"

	"errors"

	"github.com/sem-hub/snake-net/internal/aioread"
)

const first_secret = "pu6apieV6chohghah2MooshepaethuCh"
const sign_length = 64

type Secrets struct {
	sharedSecret      []byte
	sessionPrivateKey ed25519.PrivateKey
	sessionPublicKey  ed25519.PublicKey
	aio               *aioread.AioRead
}

func NewSecrets(aio *aioread.AioRead) *Secrets {
	s := Secrets{}
	s.aio = aio
	s.sessionPublicKey, s.sessionPrivateKey, _ =
		ed25519.GenerateKey(bytes.NewReader([]byte(first_secret)))

	return &s
}
func (s *Secrets) Read() ([]byte, error) {
	buf := s.aio.BlockRead()
	if len(buf) < sign_length+1 {
		return nil, errors.New("too short message")
	}
	dataLength := len(buf) - sign_length
	if !s.Verify(buf[:dataLength], buf[dataLength:]) {
		//fmt.Printf("signature verify error for the packet (len %d): %v\n", dataLength, buf[:dataLength])
		return nil, errors.New("signature verify error")
	} else {
		//fmt.Printf("signature good for the packet (len %d)\n", dataLength)
	}
	return buf[:dataLength], nil
}

func (s *Secrets) Write(buf *[]byte) error {
	signedBuf := *buf
	signature := s.Sign(buf)
	signedBuf = append(signedBuf, signature...)
	return s.aio.Write(&signedBuf)
}

func (s *Secrets) ECDH() error {
	tempPrivateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	tempPublicKey := tempPrivateKey.PublicKey()

	buf, err := x509.MarshalPKIXPublicKey(tempPublicKey)
	if err != nil {
		return errors.New("marshaling ecdh public key: " + err.Error())
	}

	//fmt.Println("Write public key (", len(buf), "): ", buf)
	err = s.Write(&buf)
	if err != nil {
		return err
	}
	//buf = buf[:0]
	//fmt.Println("Read public key: (", len(buf), "): ", buf)
	buf, err = s.Read()
	if err != nil {
		return err
	}

	publicKey, err := x509.ParsePKIXPublicKey(buf)
	if err != nil {
		return errors.New("parsing marshaled ecdh public key: " + err.Error())
	}
	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("converting marshaled public key to ecdsa public key")

	}
	parsedKey, _ := ecdsaPublicKey.ECDH()

	s.sharedSecret, err = tempPrivateKey.ECDH(parsedKey)
	if err != nil {
		return err
	}
	//fmt.Println("shared secret: ", s.sharedSecret)
	s.sessionPublicKey, s.sessionPrivateKey, err =
		ed25519.GenerateKey(bytes.NewReader(s.sharedSecret))
	if err != nil {
		return err
	}
	return nil
}

func (s *Secrets) GetPublicKey() *ed25519.PublicKey {
	return &s.sessionPublicKey
}

func (s *Secrets) GetPrivateKey() *ed25519.PrivateKey {
	return &s.sessionPrivateKey
}

func (s *Secrets) Verify(msg []byte, sig []byte) bool {
	return ed25519.Verify(s.sessionPublicKey, msg, sig)
}

func (s *Secrets) Sign(msg *[]byte) []byte {
	return ed25519.Sign(s.sessionPrivateKey, *msg)
}
