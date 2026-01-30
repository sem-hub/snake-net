package interfaces

// TunInterface represents a TUN network interface for preventing import cycles
type TunInterface interface {
	WriteTun(data []byte) error
	Close()
}
