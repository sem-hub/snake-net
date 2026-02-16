package header

type Cmd byte

const (
	NoneCmd Cmd = iota
	// Commands
	ShutdownRequest = 1
	ShutdownNotify  = 2
	AskForResend    = 3
	Ping            = 4
	Pong            = 5
	// Flags
	NoEncryption = 0x80
	NoSignature  = 0x40
	WithPadding  = 0x20
)

const FlagsMask Cmd = 0xf0
const CmdMask Cmd = 0x0f

const HEADER = 9 // 2 bytes size + 2 bytes sequence number + 1 byte flags + 4 bytes CRC32

type Header struct {
	Size  uint16
	Seq   uint16
	Flags Cmd
}

type HeaderWithCRC struct {
	Header
	CRC uint32
}
