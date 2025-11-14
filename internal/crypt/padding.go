package crypt

import (
	"bytes"
	"errors"
	"math/rand"
)

func Pad(buf []byte) []byte {
	padLen := rand.Intn(128)
	if buf == nil {
		buf = make([]byte, 0)
	}
	buf = append(buf, bytes.Repeat([]byte{byte(padLen)}, padLen)...)
	return buf
}

func UnPad(buf []byte) ([]byte, error) {
	bufLen := len(buf)
	pad := buf[bufLen-1]
	padLen := int(pad)
	// Be sure we did not remove useful data
	for _, v := range buf[bufLen-padLen : bufLen-1] {
		if v != pad {
			return nil, errors.New("crypto/padding: invalid padding")
		}
	}
	return buf[:bufLen-padLen], nil
}
