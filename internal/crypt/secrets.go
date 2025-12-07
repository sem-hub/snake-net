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
	"github.com/sem-hub/snake-net/internal/crypt/engines/block"
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
	if cipher == "aes" {
		cipher = "aes-" + mode
	}
	s.logger.Info("Cipher parameters", "cipher", cipher, "size", size, "mode", mode)
	var err error = nil
	switch cipher {
	case "aes-cbc":
		s.logger.Info("Using AES-CBC block cipher")
		s.Engine, err = block.NewAesCbcEngine(s.sharedSecret, size)
	case "present":
		s.logger.Info("Using Present block cipher")
		s.Engine, err = block.NewPresentEngine(s.sharedSecret, size)
	case "idea":
		s.logger.Info("Using Idea block cipher")
		s.Engine, err = block.NewIdeaEngine(s.sharedSecret)
	case "twofish":
		s.logger.Info("Using Twofish block cipher")
		s.Engine, err = block.NewTwofishEngine(s.sharedSecret, size)
	case "threefish":
		s.logger.Info("Using Threefish block cipher")
		s.Engine, err = block.NewThreefishEngine(s.sharedSecret, size)
	case "rc6":
		s.logger.Info("Using RC6 block cipher")
		s.Engine, err = block.NewRc6Engine(s.sharedSecret, size)
	case "serpent":
		s.logger.Info("Using Serpent block cipher")
		s.Engine, err = block.NewSerpentEngine(s.sharedSecret, size)
	case "camellia":
		s.logger.Info("Using Camellia block cipher")
		s.Engine, err = block.NewCamelliaEngine(s.sharedSecret, size)
	case "gost":
		s.logger.Info("Using GOST block cipher")
		s.Engine, err = block.NewGostEngine(s.sharedSecret)
	case "aes-ctr":
		s.logger.Info("Using AES-CTR stream cipher")
		s.Engine, err = stream.NewAesCtrEngine(s.sharedSecret, size)
	case "salsa20":
		s.logger.Info("Using Salsa20 stream cipher")
		s.Engine, err = stream.NewSalsa20Engine(s.sharedSecret)
	case "chacha20":
		s.logger.Info("Using ChaCha20 stream cipher")
		s.Engine, err = stream.NewChacha20Engine(s.sharedSecret)
	case "rabbit":
		s.logger.Info("Using Rabbit stream cipher")
		s.Engine, err = stream.NewRabbitEngine(s.sharedSecret)
	case "aes-gcm":
		s.logger.Info("Using AES-GCM AEAD cipher")
		s.Engine, err = aead.NewAesGcmEngine(s.sharedSecret, size)
	case "aes-ccm":
		s.logger.Info("Using AES-CCM AEAD cipher")
		s.Engine, err = aead.NewAesCcmEngine(s.sharedSecret, size)
	case "aes-ocb":
		s.logger.Info("Using AES-OCB AEAD cipher")
		s.Engine, err = aead.NewAesOcbEngine(s.sharedSecret, size)
	case "chacha20poly1305":
		s.logger.Info("Using ChaCha20-Poly1305 AEAD cipher")
		s.Engine, err = aead.NewChacha20Poly1305Engine(s.sharedSecret)
	case "xsalsa20poly1305":
		s.logger.Info("Using XSalsa20-Poly1305 AEAD cipher")
		s.Engine, err = aead.NewXsalsa20Poly1305Engine(s.sharedSecret)
	default:
		s.logger.Info("Unknown cipher")
		return nil, errors.New("unknown cipher: " + engine)
	}
	if err != nil {
		s.logger.Error("Failed to create crypto engine", "error", err)
		return nil, err
	}

	switch signEngine {
	case "ed25519":
		s.logger.Info("Using Ed25519 signature engine")
		s.SignatureEngine = signature.NewSignatureEd25519(s.sharedSecret)
	case "hmac-sha256":
		s.logger.Info("Using HMAC-SHA256 signature engine")
		s.SignatureEngine = signature.NewSignatureHMACSHA256(s.sharedSecret)
	case "hmac-blake2b":
		s.logger.Info("Using HMAC-Blake2b signature engine")
		s.SignatureEngine = signature.NewSignatureHMACBlake(s.sharedSecret)
	default:
		s.logger.Error("Unknown signature engine: " + engine)
		return nil, errors.New("unknown signature engine: " + signEngine)
	}
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
