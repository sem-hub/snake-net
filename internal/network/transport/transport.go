package transport

import (
	"container/list"
	"log"
	"net"
	"sync"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/songgao/water"
)

type Message = []byte

type Transport interface {
	Init(*configs.Config) error
	WaitConnection(*configs.Config, *water.Interface, func(Transport, net.Conn, net.Addr, *water.Interface)) error
	Send(net.Addr, net.Conn, *Message) error
	Receive(net.Conn) (*Message, int, net.Addr, error)
	Close() error
	GetClientConn() net.Conn
	GetFromBuf(net.Addr) []byte
}

type TransportData struct {
	globalReadBufList *list.List
	lock              *sync.Mutex
}

type listElement struct {
	addr net.Addr
	buf  []byte
}

func NewTransport(c *configs.Config) *TransportData {
	return &TransportData{list.New(), new(sync.Mutex)}
}

func (t *TransportData) PutToBuf(addr net.Addr, buf []byte) {
	log.Printf("PutToBuf %d for %s", len(buf), addr)
	newElement := listElement{addr, buf}
	t.lock.Lock()
	defer t.lock.Unlock()
	t.globalReadBufList.PushBack(newElement)
}

func (t *TransportData) GetFromBuf(addr net.Addr) []byte {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.globalReadBufList.Len() == 0 {
		return nil
	}

	var found []byte = nil
	for e := t.globalReadBufList.Front(); e != nil; e = e.Next() {
		var element listElement = e.Value.(listElement)
		if element.addr.String() == addr.String() {
			found = make([]byte, len(element.buf))
			copy(found, element.buf)
			t.globalReadBufList.Remove(e)
			log.Printf("GetFromBuf. Found data (%d) for %s", len(found), element.addr)
		}
	}
	return found
}
