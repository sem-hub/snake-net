package protocol

import (
	"errors"
	"net"
	"strings"

	"github.com/sem-hub/snake-net/internal/clients"
	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/crypt"
	"github.com/sem-hub/snake-net/internal/network"
	"github.com/sem-hub/snake-net/internal/network/transport"
)

func IdentifyClient(c *clients.Client) (net.Addr, error) {
	buf, err := c.ReadBuf()
	if err != nil {
		return nil, err
	}
	if len(buf) < 6 {
		return nil, errors.New("invalid buffer length")
	}
	h := string(buf[:6])
	clientNet := string(buf[6:])
	if h == "Hello " {
		ip, _, err := net.ParseCIDR(clientNet)
		if err != nil {
			return nil, err
		}
		_, myNetwork, err := net.ParseCIDR(configs.GetConfig().TunAddr)
		if err != nil {
			return nil, err
		}
		if !myNetwork.Contains(ip) {
			buf = []byte("Error: IP not in " + myNetwork.String())
			c.Write(&buf)

			return nil, errors.New("Client IP " + ip.String() + " not in " +
				myNetwork.String())
		}
		var addr net.Addr = &net.IPAddr{IP: ip}
		configs.GetLogger().Debug("IdentifyClient", "addr", addr)
		buf = []byte("Welcome")
		c.Write(&buf)
		return addr, nil
	} else {
		buf = []byte("Error")
		c.Write(&buf)
		return nil, errors.New("Identification error")
	}
}

func Identification(c *clients.Client) error {
	logger := configs.GetLogger()
	msg := []byte("Hello " + configs.GetConfig().TunAddr)
	logger.Debug("Identification", "msg", string(msg))
	err := c.Write(&msg)
	if err != nil {
		return err
	}

	msg1, err := c.ReadBuf()
	if err != nil {
		return err
	}
	logger.Debug("ID", "msg", string(msg1))
	if !strings.HasPrefix(string(msg1), "Welcome") {
		return errors.New("Identification " + string(msg1))
	}
	return nil
}

func ProcessNewClient(t transport.Transport, conn net.Conn, gotAddr net.Addr) {
	logger := configs.GetLogger()
	logger.Debug("ProcessNewClient", "gotAddr", gotAddr)

	addr := conn.RemoteAddr()
	logger.Debug("ProcessNewClient", "conn.RemoteAddr()", addr)
	if addr == nil {
		addr = gotAddr
	}
	c := clients.NewClient(addr, t, conn)
	s := crypt.NewSecrets(addr, t, conn)
	c.AddSecretsToClient(s)
	c.RunNetLoop(addr)

	clientIP, err := IdentifyClient(c)
	if err != nil {
		logger.Debug("Identification failed", "error", err)
		// XXX close connection, remove client
		if t.GetName() == "tcp" {
			tcpconn := conn.(*net.TCPConn)
			tcpconn.Close()
		}
		//s.Close()
		clients.RemoveClient(addr)
		return
	}
	logger.Debug("Identification passed", "clientIP", clientIP)
	c.AddTunAddressToClient(clientIP)

	c.SetClientState(clients.Authenticated)

	if err := c.ECDH(); err != nil {
		logger.Error("ECDH", "error", err)
	}

	c.SetClientState(clients.Ready)
	//fmt.Println("Session public key: ", c.GetPublicKey())
	network.ProcessTun("server", c)
}

func ProcessServer(t transport.Transport, addr net.Addr) {
	logger := configs.GetLogger()
	conn := t.GetMainConn()
	if conn == nil {
		return
	}
	// Well, really it's server but we call it client here
	c := clients.NewClient(addr, t, conn)
	s := crypt.NewSecrets(addr, t, conn)
	c.AddSecretsToClient(s)

	c.RunNetLoop(addr)

	if err := Identification(c); err == nil {
		logger.Debug("Identification Success")
	} else {
		logger.Debug("Identification Fails", "error", err)
		return
	}

	c.SetClientState(clients.Authenticated)

	if err := c.ECDH(); err != nil {
		logger.Error("ECDH", "error", err)
	}

	c.SetClientState(clients.Ready)

	//fmt.Println("Session public key: ", c.GetPublicKey())
	network.ProcessTun("client", c)
}
