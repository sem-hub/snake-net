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

	//lint:ignore ST1001 reason: it's safer to use . import here to avoid name conflicts
	. "github.com/sem-hub/snake-net/internal/protocol/header"
)

func (c *Client) ECDH() error {
	// Make a temporary ecdh key pair, marshal and send the public key
	// Read peer's public key, unmarshal and compute shared secret
	// From the shared secret, make an ed25519 key pair for signing
	tempPrivateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	tempPublicKey := tempPrivateKey.PublicKey()

	buf, err := x509.MarshalPKIXPublicKey(tempPublicKey)
	if err != nil {
		return errors.New("marshaling ecdh public key: " + err.Error())
	}

	c.logger.Trace("ECDH: Write public key", "len", len(buf), "buf", hex.EncodeToString(buf))
	err = c.Write(&buf, WithPadding)
	if err != nil {
		return err
	}

	// Read peer's public key
	buf, err = c.ReadBuf(HEADER)
	if err != nil {
		return err
	}
	c.logger.Trace("ECDH: Read public key", "len", len(buf), "buf", hex.EncodeToString(buf))

	publicKey, err := x509.ParsePKIXPublicKey(buf)
	if err != nil {
		return errors.New("parsing marshaled ecdh public key: " + err.Error())
	}
	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("converting marshaled public key to ecdsa public key")

	}
	parsedKey, _ := ecdsaPublicKey.ECDH()

	sharedSecret, err := tempPrivateKey.ECDH(parsedKey)
	if err != nil {
		return err
	}
	sessionPublicKey, sessionPrivateKey, err :=
		ed25519.GenerateKey(bytes.NewReader(sharedSecret))
	if err != nil {
		return err
	}
	// Save the shared secret and session keys
	c.logger.Trace("ECDH:", "shared secret", hex.EncodeToString(sharedSecret))
	c.secrets.SetSharedSecret(sharedSecret)
	if c.secrets.SignatureEngine != nil {
		c.secrets.SignatureEngine.SetSharedSecret(sharedSecret)
		c.secrets.SignatureEngine.SetPublicKey(sessionPublicKey)
		c.secrets.SignatureEngine.SetPrivateKey(sessionPrivateKey)
	}
	return nil
}
