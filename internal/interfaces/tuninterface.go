package interfaces

type TunInterface interface {
	WriteTun(data []byte) error
	Close()
}
