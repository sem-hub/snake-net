package clients

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"

	"github.com/sem-hub/snake-net/internal/configs"
)

func (c *Client) ECDH() error {
	// Make a temporary ecdh key pair, marshal and send the public key
	// Read peer's public key, unmarshal and compute shared secret
	// From the shared secret, make an ed25519 key pair for signing
	logger := configs.GetLogger()
	tempPrivateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	tempPublicKey := tempPrivateKey.PublicKey()

	buf, err := x509.MarshalPKIXPublicKey(tempPublicKey)
	if err != nil {
		return errors.New("marshaling ecdh public key: " + err.Error())
	}

	logger.Debug("ECDH: Write public key", "len", len(buf), "buf", hex.EncodeToString(buf))
	err = c.Write(&buf, NoEncryptionCmd)
	if err != nil {
		return err
	}

	// Read peer's public key
	buf, err = c.ReadBuf(1)
	if err != nil {
		return err
	}
	logger.Debug("ECDH: Read public key", "len", len(buf), "buf", hex.EncodeToString(buf))

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
	logger.Debug("ECDH:", "shared secret", hex.EncodeToString(c.secrets.SharedSecret))

	c.secrets.SessionPublicKey, c.secrets.SessionPrivateKey, err =
		ed25519.GenerateKey(bytes.NewReader(c.secrets.SharedSecret))
	if err != nil {
		return err
	}
	return nil
}
