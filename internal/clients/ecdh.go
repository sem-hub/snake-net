package clients

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
)

func (c *Client) ECDH() error {
	tempPrivateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	tempPublicKey := tempPrivateKey.PublicKey()

	buf, err := x509.MarshalPKIXPublicKey(tempPublicKey)
	if err != nil {
		return errors.New("marshaling ecdh public key: " + err.Error())
	}

	logger.Debug("Write public key", "len", len(buf), "buf", buf)
	err = c.Write(&buf)
	if err != nil {
		return err
	}
	buf, err = c.ReadBuf()
	if err != nil {
		return err
	}
	logger.Debug("Read public key", "len", len(buf), "buf", buf)

	publicKey, err := x509.ParsePKIXPublicKey(buf)
	if err != nil {
		return errors.New("parsing marshaled ecdh public key: " + err.Error())
	}
	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("converting marshaled public key to ecdsa public key")

	}
	parsedKey, _ := ecdsaPublicKey.ECDH()

	c.secrets.SharedSecret, err = tempPrivateKey.ECDH(parsedKey)
	if err != nil {
		return err
	}
	//fmt.Println("shared secret: ", s.SharedSecret)
	c.secrets.SessionPublicKey, c.secrets.SessionPrivateKey, err =
		ed25519.GenerateKey(bytes.NewReader(c.secrets.SharedSecret))
	if err != nil {
		return err
	}
	return nil
}
