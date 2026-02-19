package crypt

import (
	"bytes"
	"errors"
	"math/rand"

	"github.com/sem-hub/snake-net/internal/configs"
)

func Pad(buf []byte) []byte {
	logger := configs.InitLogger("crypt")
	padLen := rand.Intn(128)
	// At lest 2 bytes of padding
	if padLen < 2 {
		padLen = 2
	}
	logger.Trace("Padding", "padLen", padLen)
	return append(buf, bytes.Repeat([]byte{byte(padLen)}, padLen)...)
}

func UnPad(buf []byte) ([]byte, error) {
	logger := configs.InitLogger("crypt")
	bufLen := len(buf)
	logger.Trace("UnPadding", "bufLen", bufLen)
	pad := buf[bufLen-1]
	padLen := int(pad)
	logger.Trace("UnPadding", "padLen", padLen)
	// Be sure we did not remove useful data
	for _, v := range buf[bufLen-padLen : bufLen-1] {
		if v != pad {
			return nil, errors.New("crypto/padding: invalid padding")
		}
	}
	return buf[:bufLen-padLen], nil
}
