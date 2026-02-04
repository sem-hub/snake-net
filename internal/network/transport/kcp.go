package transport

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"

	mkcp "github.com/xtaci/kcp-go/v5"
)

type KcpTransport struct {
	TransportData
	listenConn *mkcp.Listener
	conn       map[netip.AddrPort]*mkcp.UDPSession
	connLock   *sync.RWMutex
	key        []byte
}

func NewKcpTransport(key []byte) *KcpTransport {
	return &KcpTransport{
		TransportData: *NewTransport(),
		listenConn:    nil,
		conn:          make(map[netip.AddrPort]*mkcp.UDPSession),
		connLock:      &sync.RWMutex{},
		key:           key, // 32 bytes key for AES-256
	}
}

func (kcp *KcpTransport) GetName() string {
	return "kcp"
}

func (kcp *KcpTransport) GetType() string {
	return "stream"
}

func (kcp *KcpTransport) IsEncrypted() bool {
	return true
}

func (kcp *KcpTransport) Init(mode string, rAddrPort, lAddrPort netip.AddrPort,
	callback func(Transport, netip.AddrPort)) error {
	if mode == "server" {
		// Do not block
		go func() {
			kcp.listen(lAddrPort.String(), callback)
		}()
	} else {
		kcp.logger.Info("Connect", "to", rAddrPort.String())
		block, _ := mkcp.NewAESBlockCrypt(kcp.key)
		conn, err := mkcp.DialWithOptions(rAddrPort.String(), block, 10, 3)
		if err != nil {
			return errors.New("DialWithOptions() error: " + err.Error())
		}
		kcp.connLock.Lock()
		kcp.conn[rAddrPort] = conn
		kcp.connLock.Unlock()
		kcp.logger.Info("Connected to server", "rAddrPort", rAddrPort, "from", conn.LocalAddr().String())
	}

	return nil
}

func (kcp *KcpTransport) listen(addrPort string, callback func(Transport, netip.AddrPort)) error {
	kcp.logger.Info("Listen for connection", "on", addrPort)
	block, _ := mkcp.NewAESBlockCrypt(kcp.key)
	var err error
	kcp.listenConn, err = mkcp.ListenWithOptions(addrPort, block, 10, 3)
	if err != nil {
		kcp.logger.Error("ListenWithOptions()", "err", err)
		return err
	}

	for {
		conn, err := kcp.listenConn.AcceptKCP()
		if err != nil {
			kcp.logger.Error("Accept error:", "err", err)
			return err
		}

		remoteAddr := conn.RemoteAddr().(*net.UDPAddr).AddrPort()
		remoteAddr = netip.AddrPortFrom(remoteAddr.Addr().Unmap(), remoteAddr.Port())

		kcp.logger.Info("New KCP connection from", "addr", remoteAddr.String())
		kcp.connLock.Lock()
		kcp.conn[remoteAddr] = conn
		kcp.connLock.Unlock()
		go callback(kcp, remoteAddr)
	}
	/*err = conn.Close()
	if err != nil {
		kcp.logger.Error("listen Close", "error", err)
	}*/
	//return nil
}

func (kcp *KcpTransport) Send(addr netip.AddrPort, buf *Message) error {
	kcp.connLock.RLock()
	kcpconn, ok := kcp.conn[addr]
	kcp.connLock.RUnlock()
	if !ok {
		return errors.New("No such client connection: " + addr.String())
	}

	n := len(*buf)
	kcp.logger.Debug("Send data to network", "len", n)
	l, err := kcpconn.Write(*buf)
	if err != nil {
		return err
	}
	if l < n {
		return errors.New("KCP sent less data: " + strconv.Itoa(l) + " != " + strconv.Itoa(n))
	}
	return nil
}

func (kcp *KcpTransport) Receive(addr netip.AddrPort) (Message, int, error) {
	kcp.connLock.RLock()
	kstream, ok := kcp.conn[addr]
	kcp.connLock.RUnlock()
	if !ok {
		return nil, 0, errors.New("No such client connection: " + addr.String())
	}

	b := make([]byte, NETBUFSIZE)
	l, err := kstream.Read(b)
	if err != nil {
		return nil, 0, err
	}

	kcp.logger.Debug("Got data", "len", l, "from", addr.String())
	msg := Message(b)[:l]
	return msg, l, nil
}

func (kcp *KcpTransport) CloseClient(addr netip.AddrPort) error {
	kcp.logger.Debug("KCP CloseClient", "addr", addr.String())

	kcp.connLock.RLock()
	conn, ok := kcp.conn[addr]
	kcp.connLock.RUnlock()
	if !ok {
		return errors.New("No such client connection: " + addr.String())
	}

	err := conn.Close()
	if err != nil {
		return err
	}
	kcp.connLock.Lock()
	delete(kcp.conn, addr)
	kcp.connLock.Unlock()
	return nil
}

func (kcp *KcpTransport) Close() error {
	kcp.logger.Info("KCP Transport Close")
	if kcp.listenConn != nil {
		kcp.listenConn.Close()
	}

	return nil
}
