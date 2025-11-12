package clients

import (
	"crypto/rand"
	mrand "math/rand"
)

func MakePadding() []byte {
	paddingSize := mrand.Intn(128)
	padding := make([]byte, paddingSize)
	rand.Read(padding)
	return padding
}
