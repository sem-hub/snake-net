package crypt

import "crypto/ed25519"

const SIGNLEN = 64

func SignLen() int {
	return SIGNLEN
}

func (s *Secrets) Verify(msg []byte, sig []byte) bool {
	s.logger.Debug("Verify", "msg len", len(msg), "siglen", len(sig))
	return ed25519.Verify(s.sessionPublicKey, msg, sig)
}

func (s *Secrets) Sign(msg []byte) []byte {
	s.logger.Debug("Sign", "msglen", len(msg))
	return ed25519.Sign(s.sessionPrivateKey, msg)
}
