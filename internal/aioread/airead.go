package aioread

import (
	"net"

	"github.com/sem-hub/snake-net/internal/network"
	"github.com/sem-hub/snake-net/internal/queue"
)

type AioRead struct {
	q    *queue.Queue
	t    network.Transport
	conn net.Conn
}

func NewAioRead(t network.Transport, conn net.Conn) *AioRead {
	aio := &AioRead{}
	aio.t = t
	aio.conn = conn
	aio.q = queue.NewQueue()
	go func() {
		for {
			msgPtr, length, err := t.Receive(conn)
			if err != nil {
				return
			}
			var msg = make([]byte, length)
			copy(msg, *msgPtr)
			aio.q.Push(msg)
		}
	}()
	return aio
}

func (aio *AioRead) GetTransport() network.Transport {
	return aio.t
}

func (aio *AioRead) GetConn() net.Conn {
	return aio.conn
}

func (aio *AioRead) BlockRead() []byte {
	for {
		if !aio.q.IsEmpty() {
			buf, _ := aio.q.Pop().([]byte)
			return buf
		}
	}
}

func (aio *AioRead) Write(buf *[]byte) error {
	return aio.t.Send(aio.conn, buf)
}

func (aio *AioRead) Pop() []byte {
	buf, ok := aio.q.Pop().([]byte)
	if !ok {
		return nil
	}
	return buf
}

func (aio *AioRead) IsEmpty() bool {
	return aio.q.IsEmpty()
}
