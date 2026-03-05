package clients

import (
	"encoding/binary"
	"errors"
	"hash/crc32"

	"github.com/sem-hub/snake-net/internal/crypt"
	"github.com/sem-hub/snake-net/internal/network/transport"

	//lint:ignore ST1001 reason: it's safer to use . import here to avoid name conflicts
	. "github.com/sem-hub/snake-net/internal/protocol/header"
)

// We send encrypted header (HEADER bytes) + encrypted data + signature of the encrypted data (sign only data, not header)
// If transport is encrypted, we skip header encryption and do not sign (transport cares for all)
// If encryption is AEAD, we do not need to sign (integrity is provided by AEAD)
// cmd contains flags for encryption/signing and commands
func (c *Client) Write(msg *transport.Message, cmd Cmd) error {
	if c.t.IsEncrypted() {
		// Transport does low-level encryption, so we can skip it
		cmd |= NoEncryption
		cmd |= NoSignature
	}
	if !c.secrets.SignatureEngine.IsActive() {
		cmd |= NoSignature
	}

	// It's possible we have msg == nil. It means we only want to send a command without data. Padding will be added to these packets.
	n := 0
	if msg == nil {
		c.logger.Debug("client Write: no data. Send a command only", "address", c.address)
		cmd |= WithPadding
	} else {
		n = len(*msg)
		c.logger.Debug("client Write data", "len", n, "address", c.address)

		addLen := 0
		if c.secrets.SignatureEngine != nil && (cmd&NoSignature) == 0 {
			addLen = int(c.secrets.SignatureEngine.SignLen())
		}
		if HEADER+n+addLen > BUFSIZE {
			return errors.New("invalid message size")
		}
	}
	// Copy message only when padding is needed to avoid mutating caller buffer.
	c.logger.Debug("client Write", "address", c.address, "seq", c.seqOut.Load())

	var msgBuf []byte
	if msg != nil {
		msgBuf = *msg
	}
	// Need padding
	if (cmd & WithPadding) != 0 {
		if msgBuf != nil {
			msgBuf = append([]byte(nil), msgBuf...)
		}
		msgBuf = crypt.Pad(msgBuf)
	}

	buf := make([]byte, HEADER)

	var err error
	if c.secrets.Engine != nil || (cmd&NoEncryption) == 0 {
		msgBuf, err = c.secrets.SignAndEncrypt(msgBuf, cmd)
		if err != nil {
			c.logger.Error("client Write SignAndEncrypt error", "error", err, "address", c.address, "seq", c.seqOut.Load())
			return err
		}
	}
	buf = append(buf, msgBuf...)

	n = len(buf) - HEADER

	req := sendRequest{
		buf:        buf,
		seq:        0,
		result:     make(chan error, 1),
		isPriority: (cmd & CmdMask) != NoneCmd,
	}

	c.sendQueueLock.Lock()
	seq := c.seqOut.Add(1) % 65536
	if seq == 0 {
		c.seqOut.Store(1)
		seq = 1
		c.logger.Warn("client Write sequence number wrapped around, resetting to", "seq", seq, "address", c.address)
	}
	req.seq = uint16(seq)

	var headerBuf [HEADER]byte
	binary.BigEndian.PutUint16(headerBuf[0:2], uint16(n))
	binary.BigEndian.PutUint16(headerBuf[2:4], uint16(seq))
	headerBuf[4] = byte(cmd)

	crc := crc32.ChecksumIEEE(headerBuf[:5])
	c.logger.Debug("client Write", "crc", crc)
	binary.BigEndian.PutUint32(headerBuf[5:9], crc)

	// Encrypt header if transport is not Encrypted. Must not change message size!
	if !c.t.IsEncrypted() {
		encryptData, err := c.secrets.EncryptDecryptNoIV(headerBuf[:])
		if err != nil {
			c.sendQueueLock.Unlock()
			return err
		}
		copy(req.buf[:HEADER], encryptData)
	} else {
		copy(req.buf[:HEADER], headerBuf[:])
	}

	c.logger.Debug("client Write final", "address", c.address, "n", n, "bufsize", len(req.buf))

	if req.isPriority {
		select {
		case c.prioSendQueue <- req:
			c.sendQueueLock.Unlock()
			return <-req.result
		case <-c.sendLoopDone:
			c.sendQueueLock.Unlock()
			return errors.New("client is closed")
		}
	}

	select {
	case c.sendQueue <- req:
		c.sendQueueLock.Unlock()
		return <-req.result
	case <-c.sendLoopDone:
		c.sendQueueLock.Unlock()
		return errors.New("client is closed")
	}
}

func (c *Client) runSendLoop() {
	for {
		var req sendRequest
		//var hasPriority bool

		select {
		// Signal to stop the loop and exit the goroutine
		case <-c.sendLoopDone:
			return
		default:
		}

		select {
		case req = <-c.prioSendQueue:
			//hasPriority = true
		case req = <-c.sendQueue:
			//hasPriority = false
		case <-c.sendLoopDone:
			return
		}

		err := c.t.Send(c.address, &req.buf)
		if err != nil {
			c.logger.Error("client Write send error", "error", err, "address", c.address, "seq", req.seq)
			req.result <- err
			continue
		}
		c.logger.Debug("client Write sent", "len", len(req.buf), "address", c.address, "seq", req.seq)
		// Save to sent circular buffer
		c.sentBuffer.Push(req.buf)
		req.result <- nil
	}
}
