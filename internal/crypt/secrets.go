package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"strconv"
	"strings"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/crypt/engines"
	"github.com/sem-hub/snake-net/internal/crypt/signature"

	//lint:ignore ST1001 reason: it's safer to use . import here to avoid name conflicts
	. "github.com/sem-hub/snake-net/internal/protocol/header"

	// Import all engine implementations to register them
	_ "github.com/sem-hub/snake-net/internal/crypt/engines/aead"
	_ "github.com/sem-hub/snake-net/internal/crypt/engines/ciphers"
	_ "github.com/sem-hub/snake-net/internal/crypt/engines/stream"
)

type Secrets struct {
	sharedSecret    []byte
	Engine          engines.CryptoEngine
	SignatureEngine signature.SignatureInterface
	// For EncryptDecryptNoIV
	iv    [aes.BlockSize]byte
	block cipher.Block
}

func NewSecrets(engine, secret, signEngine string) (*Secrets, error) {
	s := Secrets{}
	logger := configs.GetLogger("crypt")
	s.sharedSecret = make([]byte, 32)
	sum256 := sha256.Sum256([]byte(secret))
	copy(s.sharedSecret, sum256[:])

	var err error
	s.SignatureEngine, err = CreateSignatureEngine(signEngine, s.sharedSecret)
	if err != nil {
		logger.Error("Failed to create signature engine", "error", err)
		return nil, err
	}
	logger.Info("Using " + signEngine + " signature engine")

	sessionPublicKey, sessionPrivateKey, err := ed25519.GenerateKey(bytes.NewReader([]byte(s.sharedSecret)))
	if err != nil {
		logger.Error("Failed to generate session keys", "error", err)
		return nil, err
	}
	s.SignatureEngine.SetPublicKey(sessionPublicKey)
	s.SignatureEngine.SetPrivateKey(sessionPrivateKey)

	// Don't need to setup crypto engine
	if engine == "" {
		return &s, nil
	}
	size := 0
	cipherStr := engine
	mode := ""
	parts := strings.Split(engine, "-")
	if len(parts) > 0 {
		cipherStr = parts[0]
	}
	if len(parts) > 1 {
		if strconvVal, err := strconv.Atoi(parts[1]); err == nil {
			size = strconvVal
			if len(parts) > 2 {
				mode = parts[2]
			}
		} else {
			mode = parts[1]
		}
	}
	// Default mode for block ciphers is CBC, for stream and AEAD it's not needed.
	if mode == "" && engines.GetEngineType(cipherStr) == "block" {
		mode = "cbc"
	}
	logger.Debug("Cipher parameters", "cipher", cipherStr, "size", size, "mode", mode)
	s.Engine, err = CreateEngine(cipherStr, mode, size, s.sharedSecret)
	if err != nil {
		logger.Error("Failed to create crypto engine", "error", err)
		return nil, err
	}
	if mode != "" {
		cipherStr += "-" + mode
	}
	logger.Info("Using", "cipher", cipherStr)
	logger.Debug("GetOverhead", "overhead", s.Engine.GetOverhead())

	if s.Engine.GetType() == "aead" {
		s.SignatureEngine.Deactivate()
		logger.Info("AEAD cipher selected, signature engine will not be used")
	}

	// For EncryptDecryptNoIV
	s.block, err = aes.NewCipher(s.sharedSecret)
	if err != nil {
		return nil, err
	}

	return &s, nil
}

func (s *Secrets) SetSharedSecret(secret []byte) {
	s.sharedSecret = secret
}

func (s *Secrets) GetSharedSecret() []byte {
	return s.sharedSecret
}

// We just make zero IV and don't keep it. So len(data) == len(bufOut) (constant size and symmetric operation)
func (s *Secrets) EncryptDecryptNoIV(data []byte) ([]byte, error) {
	logger := configs.GetLogger("crypt")
	logger.Trace("EncryptNoIV", "datalen", len(data))

	// empty IV
	stream := cipher.NewCTR(s.block, s.iv[:])

	bufOut := make([]byte, len(data))
	stream.XORKeyStream(bufOut, data)
	return bufOut, nil
}

func (s *Secrets) DecryptAndVerify(msg []byte, n uint16, flags Cmd) ([]byte, error) {
	logger := configs.GetLogger("crypt")
	if s.Engine != nil && s.Engine.GetType() == "aead" {
		flags |= NoSignature
	}
	length := int(n)
	if length > len(msg) {
		return nil, errors.New("DecryptAndVerify: invalid packet length")
	}

	signLen := 0
	var signature []byte
	// Save signature
	if (flags & NoSignature) == 0 {
		signLen = int(s.SignatureEngine.SignLen())
		if signLen > length {
			return nil, errors.New("DecryptAndVerify: invalid signature length")
		}
		signature = msg[length-signLen : length]
	}

	payloadEnd := length - signLen
	var buf []byte
	// decrypt and verify the packet or just verify if NoEncryptionCmd flag set
	if (flags & NoEncryption) == 0 {
		logger.Trace("Decrypting")
		data, err := s.Engine.Decrypt(msg[:payloadEnd])
		if err != nil {
			logger.Error("DecryptAndVerify error", "error", err)
			return nil, err
		}
		logger.Trace("After decryption", "datalen", len(data), "msglen", len(msg))
		buf = data
	} else {
		buf = msg[:payloadEnd]
	}
	if (flags & NoSignature) == 0 {
		if !s.SignatureEngine.Verify(buf, signature) {
			logger.Error("DecryptAndVerify: verify error")
			return nil, errors.New("verify error")
		}
		logger.Trace("Signature verified")
	}
	return buf, nil
}

func (s *Secrets) SignAndEncrypt(msg []byte, flags Cmd) ([]byte, error) {
	logger := configs.GetLogger("crypt")
	if s.Engine != nil && s.Engine.GetType() == "aead" {
		flags |= NoSignature
	}

	var buf []byte
	if (flags & NoEncryption) == 0 {
		logger.Trace("client Write encrypting", "len", len(msg))
		data, err := s.Engine.Encrypt(msg)
		if err != nil {
			return nil, err
		}
		buf = data
	} else {
		if (flags&NoSignature) == 0 && s.SignatureEngine != nil {
			buf = make([]byte, len(msg), len(msg)+int(s.SignatureEngine.SignLen()))
			copy(buf, msg)
		} else {
			buf = msg
		}
	}

	// Sign BEFORE encryption
	// Unencrypted signature at the end
	if (flags & NoSignature) == 0 {
		logger.Debug("client Write signing")
		signature := s.SignatureEngine.Sign(msg)
		buf = append(buf, signature...)
	}
	logger.Trace("client Write SignAndEncrypt done", "len", len(buf))
	return buf, nil
}

func CreateEngine(engineName, mode string, keySize int, sharedSecret []byte) (engines.CryptoEngine, error) {
	logger := configs.GetLogger("crypt")
	if !engines.IsEngineAvailable(engineName) {
		logger.Error("Engine not available", "engine", engineName, "available", engines.GetAvailableEngines())
		return nil, errors.New("engine " + engineName + " is not available (may require build tag)")
	}
	return engines.NewEngineByName(engineName, sharedSecret, keySize, mode)
}

func CreateSignatureEngine(signEngine string, sharedSecret []byte) (signature.SignatureInterface, error) {
	logger := configs.GetLogger("crypt")
	if !signature.IsSignatureEngineAvailable(signEngine) {
		logger.Error("Signature engine not available", "engine", signEngine, "available", signature.GetAvailableSignatureEngines())
		return nil, errors.New("signature engine " + signEngine + " is not available (may require build tag)")
	}
	return signature.NewSignatureEngineByName(signEngine, sharedSecret)
}
