package network

import (
	"crypto/sha256"
	"math/rand"
	"net"
	"strconv"
	"time"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/crypt/engines"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var cEngine engines.CryptoEngine

const IDSTRING = "SNAKE_NET_PORT_REQUEST"

func StartICMPListen(secret string) {
	secretBin := make([]byte, 32)
	sum256 := sha256.Sum256([]byte(secret))
	copy(secretBin, sum256[:])

	var err error
	cEngine, err = engines.NewEngineByName("aes", secretBin, 256, "gcm")
	if err != nil {
		configs.InitLogger("icmp").Fatal("Error initializing crypto engine", "error", err)
	}
	go func() {
		StartICMPCommonListen(true)
	}()
	go func() {
		StartICMPCommonListen(false)
	}()
}

func isOurPacket(data []byte) bool {
	logger := configs.InitLogger("icmp")
	buf, err := cEngine.Decrypt(data)
	if err != nil {
		logger.Debug("Error decrypting data", "error", err)
		return false
	}
	logger.Trace("Decrypted ICMP data", "data", string(buf), "len", len(buf))
	return string(buf[:len(IDSTRING)]) == IDSTRING
}

func fillData(data []byte) []byte {
	buf := make([]byte, 28)
	port, err := strconv.Atoi(string(data))
	if err == nil {
		buf[0] = byte(port >> 8)
		buf[1] = byte(port & 0xFF)
	} else {
		copy(buf, data)
	}
	encBuf, err := cEngine.Encrypt(buf)
	if err != nil {
		configs.InitLogger("icmp").Fatal("Error encrypting data", "error", err)
	}
	return encBuf
}

func decodePort(data []byte) int {
	logger := configs.InitLogger("icmp")
	logger.Debug("decodePort", "len", len(data))
	decBuf, err := cEngine.Decrypt(data)
	if err != nil {
		logger.Error("Error decrypting data", "error", err)
		return 0
	}
	if string(decBuf[:len(IDSTRING)]) == IDSTRING {
		logger.Debug("Received OS reply, ignoring")
		return 0
	}
	port := (int(decBuf[0]) << 8) | int(decBuf[1])
	return port
}

func StartICMPCommonListen(isIPv4 bool) {
	logger := configs.InitLogger("icmp")

	var icmpConn *icmp.PacketConn
	var err error
	if isIPv4 {
		icmpConn, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	} else {
		icmpConn, err = icmp.ListenPacket("ip6:ipv6-icmp", "::")
	}
	if err != nil {
		panic(err)
	}
	defer icmpConn.Close()

	// Create a buffer to read incoming packets
	buf := make([]byte, 1500)

	for {
		n, peer, err := icmpConn.ReadFrom(buf)
		if err != nil {
			logger.Fatal("Error reading ICMP packet", "error", err)
		}

		// Parse the ICMP message
		var msg *icmp.Message
		if isIPv4 {
			msg, err = icmp.ParseMessage(ipv4.ICMPTypeEcho.Protocol(), buf[:n])
		} else {
			msg, err = icmp.ParseMessage(ipv6.ICMPTypeEchoRequest.Protocol(), buf[:n])
		}
		if err != nil {
			logger.Error("Error parsing ICMP message", "error", err)
			continue
		}

		switch msg.Type {
		case ipv4.ICMPTypeEcho, ipv6.ICMPTypeEchoRequest:
			echo, ok := msg.Body.(*icmp.Echo)
			if !ok {
				logger.Error("Invalid ICMP Echo message body")
				continue
			}
			if !isOurPacket(echo.Data) {
				logger.Trace("Ignore alien packet")
				continue
			} else {
				logger.Debug("Received valid ICMP Echo with port request from", "peer", peer)
			}
			logger.Trace("Received ICMP Echo from", "peer", peer, "id", echo.ID, "seq", echo.Seq)
			// Process the echo request and send a reply
			portNo := int(configs.GetConfig().LocalPort)
			data := fillData([]byte(strconv.Itoa(portNo)))

			reply := &icmp.Message{
				Type: func(isIPv4 bool) icmp.Type {
					if isIPv4 {
						return ipv4.ICMPTypeEchoReply
					}
					return ipv6.ICMPTypeEchoReply
				}(isIPv4),
				Code: 0,
				Body: &icmp.Echo{
					ID:   echo.ID,
					Seq:  echo.Seq,
					Data: data,
				},
			}
			replyBytes, err := reply.Marshal(nil)
			if err != nil {
				logger.Error("Error marshaling ICMP message", "error", err)
				continue
			}
			if _, err := icmpConn.WriteTo(replyBytes, peer); err != nil {
				logger.Error("Error sending ICMP Echo Reply", "error", err)
				continue
			}
			logger.Debug("Sent ICMP Echo Reply to", "peer", peer, "id", echo.ID, "seq", echo.Seq)
		default:
			// Ignore other ICMP message types
		}
	}
}

func GetICMPPort(addr net.IPAddr, secret string) int {
	secretBin := make([]byte, 32)
	sum256 := sha256.Sum256([]byte(secret))
	copy(secretBin, sum256[:])

	logger := configs.InitLogger("icmp")
	logger.Debug("Asking port from server via ICMP", "peer", addr)
	var err error
	cEngine, err = engines.NewEngineByName("aes", secretBin, 256, "gcm")
	if err != nil {
		logger.Fatal("Error initializing crypto engine", "error", err)
	}

	var icmpConn *icmp.PacketConn
	if addr.IP.To4() != nil {
		icmpConn, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	} else {
		icmpConn, err = icmp.ListenPacket("ip6:ipv6-icmp", "::")
	}
	if err != nil {
		logger.Fatal("Error listening for ICMP packets", "error", err)
	}
	defer icmpConn.Close()

	data := fillData([]byte("SNAKE_NET_PORT_REQUEST"))
	id := rand.Intn(65535)
	icmpMessage := &icmp.Message{
		Type: func(isIPv4 bool) icmp.Type {
			if isIPv4 {
				return ipv4.ICMPTypeEcho
			}
			return ipv6.ICMPTypeEchoRequest
		}(addr.IP.To4() != nil),
		Code: 0,
		Body: &icmp.Echo{
			ID:   id,
			Seq:  1,
			Data: data,
		},
	}
	icmpBytes, err := icmpMessage.Marshal(nil)
	if err != nil {
		logger.Fatal("Marshaling error", "error", err)
	}
	if _, err := icmpConn.WriteTo(icmpBytes, &addr); err != nil {
		logger.Fatal("Error sending ICMP Echo", "error", err)
	}
	logger.Debug("Sent ICMP Echo to", "peer", addr.String())
	reply := make([]byte, 1500)
	if err := icmpConn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		logger.Fatal("Error setting ICMP read deadline", "error", err)
	}

	i := 0
	for {
		n, peer, err := icmpConn.ReadFrom(reply)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				logger.Debug("ICMP read timeout while waiting for Echo Reply", "peer", addr)
				return 0
			}
			logger.Error("Error receiving ICMP Echo Reply", "error", err)
			return 0
		}
		var rm *icmp.Message
		if addr.IP.To4() != nil {
			rm, err = icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), reply[:n])
		} else {
			rm, err = icmp.ParseMessage(ipv6.ICMPTypeEchoReply.Protocol(), reply[:n])
		}
		if err != nil {
			logger.Debug("Error parsing ICMP message", "error", err)
			continue
		}
		i++
		if i > 10 {
			logger.Debug("Too many ICMP messages received without valid Echo Reply, giving up", "peer", addr)
			break
		}
		switch rm.Type {
		case ipv4.ICMPTypeEchoReply, ipv6.ICMPTypeEchoReply:
			logger.Debug("Received ICMP Echo Reply from", "peer", peer)
			if echo, ok := rm.Body.(*icmp.Echo); ok {
				if echo.ID == id && echo.Seq == 1 {
					logger.Debug("Received valid ICMP Echo Reply with port request from", "peer", peer)
					port := decodePort(echo.Data)
					if port != 0 {
						logger.Debug("Received port number from ICMP Echo Reply", "peer", peer, "port", port)
						return port
					}
					// Ignore the packet
					continue
				} else {
					logger.Debug("Received ICMP Echo Reply with invalid data from", "peer", peer)
					continue
				}
			}
		default:
			logger.Debug("Received non-echo-reply ICMP message from", "peer", peer, "type", rm.Type)
			continue
		}
	}
	return 0
}
