package crypt

import (
	"bytes"
	maes "crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"log/slog"
	"strconv"
	"strings"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/crypt/engines"
	"github.com/sem-hub/snake-net/internal/crypt/engines/aead"
	"github.com/sem-hub/snake-net/internal/crypt/engines/ciphers"
	"github.com/sem-hub/snake-net/internal/crypt/engines/stream"
	"github.com/sem-hub/snake-net/internal/crypt/signature"

	//lint:ignore ST1001 reason: it's safer to use . import here to avoid name conflicts
	. "github.com/sem-hub/snake-net/internal/interfaces"
)

const FIRSTSECRET = "pu6apieV6chohghah2MooshepaethuCh"

type Secrets struct {
	logger          *slog.Logger
	sharedSecret    []byte
	Engine          engines.CryptoEngine
	SignatureEngine signature.SignatureInterface
}

var logger *slog.Logger

func NewSecrets(engine, secret, signEngine string) (*Secrets, error) {
	s := Secrets{}
	logger = configs.InitLogger("crypt")
	s.logger = logger

	s.sharedSecret = make([]byte, 32)
	if secret == "" {
		s.logger.Info("Using default shared secret")
		secret = FIRSTSECRET
	} else {
		s.logger.Info("Using provided shared secret")
	}
	sum256 := sha256.Sum256([]byte(secret))
	copy(s.sharedSecret, sum256[:])

	// Don't need to setup crypto engine and signature
	if engine == "" {
		return &s, nil
	}
	size := 0
	cipher := engine
	mode := ""
	parts := strings.Split(engine, "-")
	if len(parts) > 0 {
		cipher = parts[0]
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
	if mode == "" {
		mode = "cbc"
	}
	s.logger.Info("Cipher parameters", "cipher", cipher, "size", size, "mode", mode)
	var err error = nil
	s.Engine, err = CreateEngine(cipher, mode, size, s.sharedSecret)
	if err != nil {
		s.logger.Error("Failed to create crypto engine", "error", err)
		return nil, err
	}
	s.logger.Info("Using " + cipher + " " + mode + " cipher")

	if s.Engine.GetType() == "aead" {
		s.logger.Info("AEAD cipher selected, signature engine will not be used")
		return &s, nil
	}

	s.SignatureEngine, err = CreateSignatureEngine(signEngine, s.sharedSecret)
	if err != nil {
		s.logger.Error("Failed to create signature engine", "error", err)
		return nil, err
	}
	s.logger.Info("Using " + signEngine + " signature engine")

	sessionPublicKey, sessionPrivateKey, err := ed25519.GenerateKey(bytes.NewReader([]byte(s.sharedSecret)))
	if err != nil {
		s.logger.Error("Failed to generate session keys", "error", err)
		return nil, err
	}
	s.SignatureEngine.SetPublicKey(sessionPublicKey)
	s.SignatureEngine.SetPrivateKey(sessionPrivateKey)

	return &s, nil
}

func (s *Secrets) SetSharedSecret(secret []byte) {
	s.sharedSecret = secret
}

func (s *Secrets) GetSharedSecret() []byte {
	return s.sharedSecret
}

// We just make zero IV and don't keep it.
// So len(data) == len(bufOut)
func (s *Secrets) EncryptDecryptNoIV(data []byte) ([]byte, error) {
	s.logger.Debug("EncryptNoIV", "datalen", len(data))

	block, err := maes.NewCipher(s.sharedSecret)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, maes.BlockSize)
	stream := cipher.NewCTR(block, iv)

	bufOut := make([]byte, len(data))
	stream.XORKeyStream(bufOut, data)
	return bufOut, nil
}

func (s *Secrets) DecryptAndVerify(msg []byte, n int, flags Cmd) ([]byte, error) {
	if s.Engine.GetType() == "aead" {
		flags |= NoSignature
	}
	buf := make([]byte, 0)
	signLen := 0
	var signature []byte
	// Save signature
	if (flags & NoSignature) == 0 {
		signLen = s.SignatureEngine.SignLen()
		signature = msg[n-signLen : n]
	}
	// decrypt and verify the packet or just verify if NoEncryptionCmd flag set
	if (flags & NoEncryption) == 0 {
		s.logger.Debug("Decrypting")
		data, err := s.Engine.Decrypt(msg[:n-signLen])
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
		if !s.SignatureEngine.Verify(buf, signature) {
			s.logger.Error("DecryptAndVerify: verify error")
			return nil, errors.New("verify error")
		}
		s.logger.Debug("Signature verified")
	}
	return buf, nil
}

func (s *Secrets) SignAndEncrypt(msg []byte, flags Cmd) ([]byte, error) {
	if s.Engine.GetType() == "aead" {
		flags |= NoSignature
	}

	buf := make([]byte, 0)
	if (flags & NoEncryption) == 0 {
		s.logger.Debug("client Write encrypting", "len", len(msg))
		data, err := s.Engine.Encrypt(msg)
		if err != nil {
			return nil, err
		}
		buf = append(buf, data...)
	} else {
		buf = append(buf, msg...)
	}

	// Sign BEFORE encryption
	// Unencrypted signature at the end
	if (flags & NoSignature) == 0 {
		s.logger.Debug("client Write signing")
		signature := s.SignatureEngine.Sign(msg)
		buf = append(buf, signature...)
	}
	s.logger.Debug("client Write SignAndEncrypt done", "len", len(buf))
	return buf, nil
}

func CreateEngine(engineName, mode string, keySize int, sharedSecret []byte) (engines.CryptoEngine, error) {
	var engine engines.CryptoEngine
	var err error
	switch engineName {
	case "aes":
		engine, err = ciphers.NewAesEngine(sharedSecret, keySize, mode)
	case "speck":
		engine, err = ciphers.NewSpeckEngine(sharedSecret, keySize, mode)
	case "idea":
		engine, err = ciphers.NewIdeaEngine(sharedSecret, mode)
	case "threefish":
		engine, err = ciphers.NewThreefishEngine(sharedSecret, keySize, mode)
	case "rc6":
		engine, err = ciphers.NewRc6Engine(sharedSecret, keySize, mode)
	case "serpent":
		engine, err = ciphers.NewSerpentEngine(sharedSecret, keySize, mode)
	case "camellia":
		engine, err = ciphers.NewCamelliaEngine(sharedSecret, keySize, mode)
	case "gost":
		engine, err = ciphers.NewGostEngine(sharedSecret, mode)
	case "salsa20":
		engine, err = stream.NewSalsa20Engine(sharedSecret)
	case "chacha20":
		engine, err = stream.NewChacha20Engine(sharedSecret)
	case "rabbit":
		engine, err = stream.NewRabbitEngine(sharedSecret)
	case "hc":
		engine, err = stream.NewHc256Engine(sharedSecret)
	case "chacha20poly1305":
		engine, err = aead.NewChacha20Poly1305Engine(sharedSecret)
	case "xsalsa20poly1305":
		engine, err = aead.NewXsalsa20Poly1305Engine(sharedSecret)
	case "grain":
		engine, err = aead.NewGrainEngine(sharedSecret)
	default:
		return nil, errors.New("unknown cipher: " + engineName)
	}
	return engine, err
}

func CreateSignatureEngine(signEngine string, sharedSecret []byte) (signature.SignatureInterface, error) {
	var s signature.SignatureInterface
	switch signEngine {
	case "ed25519":
		s = signature.NewSignatureEd25519(sharedSecret)
	case "hmac-sha256":
		s = signature.NewSignatureHMACSHA256(sharedSecret)
	case "hmac-blake2b":
		s = signature.NewSignatureHMACBlake(sharedSecret)
	default:
		return nil, errors.New("unknown signature engine: " + signEngine)
	}
	return s, nil
}
