package crypt

import (
	"bytes"
	maes "crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"log/slog"

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
	SecretsInterface
	logger            *slog.Logger
	sharedSecret      []byte
	sessionPrivateKey ed25519.PrivateKey
	sessionPublicKey  ed25519.PublicKey
	engine            engines.CryptoEngine
	SignatureEngine   SignatureInterface
}

var logger *slog.Logger

func NewSecrets(engine, secret string) *Secrets {
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
	s.sessionPublicKey, s.sessionPrivateKey, _ =
		ed25519.GenerateKey(bytes.NewReader([]byte(s.sharedSecret)))

	switch engine {
	case "aes-ctr":
		s.logger.Info("Using AES-CTR stream cipher")
		s.engine = stream.NewAesCtrEngine(s.sharedSecret)
	case "aes-cbc":
		s.logger.Info("Using AES-CBC block cipher")
		s.engine = block.NewAesCbcEngine(s.sharedSecret)
	case "present":
		s.logger.Info("Using Present block cipher")
		s.engine = block.NewPresentEngine(s.sharedSecret)
	case "idea":
		s.logger.Info("Using Idea block cipher")
		s.engine = block.NewIdeaEngine(s.sharedSecret)
	case "twofish":
		s.logger.Info("Using Twofish block cipher")
		s.engine = block.NewTwofishEngine(s.sharedSecret)
	case "threefish":
		s.logger.Info("Using Threefish block cipher")
		s.engine = block.NewThreefishEngine(s.sharedSecret)
	case "rc6":
		s.logger.Info("Using RC6 block cipher")
		s.engine = block.NewRc6Engine(s.sharedSecret)
	case "aes-gcm":
		s.logger.Info("Using AES-GCM AEAD cipher")
		s.engine = aead.NewAesGcmEngine(s.sharedSecret)
	case "aes-ccm":
		s.logger.Info("Using AES-CCM AEAD cipher")
		s.engine = aead.NewAesCcmEngine(s.sharedSecret)
	case "salsa20":
		s.logger.Info("Using Salsa20 stream cipher")
		s.engine = stream.NewSalsa20Engine(s.sharedSecret)
	case "chacha20":
		s.logger.Info("Using ChaCha20 stream cipher")
		s.engine = stream.NewChacha20Engine(s.sharedSecret)
	case "rabbit":
		s.logger.Info("Using Rabbit stream cipher")
		s.engine = stream.NewRabbitEngine(s.sharedSecret)
	case "chacha20poly1305":
		s.logger.Info("Using ChaCha20-Poly1305 AEAD cipher")
		s.engine = aead.NewChacha20Poly1305Engine(s.sharedSecret)
	case "xsalsa20poly1305":
		s.logger.Info("Using XSalsa20-Poly1305 AEAD cipher")
		s.engine = aead.NewXsalsa20Poly1305Engine(s.sharedSecret)
	default:
		s.logger.Info("Unknown cipher")
		return nil
	}
	return &s
}

func (s *Secrets) CreateSignatureEngine(engine string) error {
	switch engine {
	case "ed25519":
		s.logger.Info("Using Ed25519 signature engine")
		s.SignatureEngine = signature.NewSignatureEd25519(s)
	case "hmac-sha256":
		s.logger.Info("Using HMAC-SHA256 signature engine")
		s.SignatureEngine = signature.NewSignatureHMACSHA256(s)
	default:
		s.logger.Error("Unknown signature engine: " + engine)
		return errors.New("unknown signature engine: " + engine)
	}
	return nil
}

func (s *Secrets) SetPublicKey(pub ed25519.PublicKey) {
	s.sessionPublicKey = pub
}

func (s *Secrets) SetPrivateKey(priv ed25519.PrivateKey) {
	s.sessionPrivateKey = priv
}

func (s *Secrets) SetSharedSecret(secret []byte) {
	s.sharedSecret = secret
}

func (s *Secrets) GetPublicKey() *ed25519.PublicKey {
	return &s.sessionPublicKey
}

func (s *Secrets) GetPrivateKey() *ed25519.PrivateKey {
	return &s.sessionPrivateKey
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
	if s.engine.GetType() == "aead" {
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
		data, err := s.engine.Decrypt(msg[:n-signLen])
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
	if s.engine.GetType() == "aead" {
		flags |= NoSignature
	}

	buf := make([]byte, 0)
	if (flags & NoEncryption) == 0 {
		s.logger.Debug("client Write encrypting", "len", len(msg))
		data, err := s.engine.Encrypt(msg)
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
