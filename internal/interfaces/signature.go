package interfaces

type SignatureInterface interface {
	Sign(msg []byte) []byte
	Verify(msg []byte, sig []byte) bool
	SignLen() int
}
