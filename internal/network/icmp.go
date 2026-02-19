package network

import (
	"math/rand"
	"net"
	"time"

	"github.com/sem-hub/snake-net/internal/configs"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func StartICMPListen() {
	go func() {
		StartICMPCommonListen(true)
	}()
	go func() {
		StartICMPCommonListen(false)
	}()
}

func isOurPacket(data []byte) bool {
	return string(data) == "SNAKE_NET_PORT_REQUEST"
}

func fiilData(port uint16) []byte {
	logger := configs.InitLogger("icmp")
	logger.Debug("Filling ICMP data with port", "port", port)
	data := make([]byte, 3)
	data[0] = 0xff
	data[1] = byte(port >> 8)
	data[2] = byte(port & 0xFF)
	return data
}

func decodePort(data []byte) int {
	port := (int(data[1]) << 8) | int(data[2])
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
			}
			logger.Trace("Received ICMP Echo from", "peer", peer, "id", echo.ID, "seq", echo.Seq)
			// Process the echo request and send a reply
			data := fiilData(configs.GetConfig().LocalPort)

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

func GetICMPPort(addr string) int {
	logger := configs.InitLogger("icmp")
	logger.Debug("Asking port from server via ICMP", "peer", addr)

	icmpConn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		logger.Fatal("Error listening for ICMP packets", "error", err)
	}
	defer icmpConn.Close()

	data := []byte("SNAKE_NET_PORT_REQUEST")
	id := rand.Intn(65535)
	icmpMessage := &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
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
	if _, err := icmpConn.WriteTo(icmpBytes, &net.IPAddr{IP: net.ParseIP(addr)}); err != nil {
		logger.Fatal("Error sending ICMP Echo", "error", err)
	}
	logger.Debug("Sent ICMP Echo to", "peer", addr)
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
		rm, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), reply[:n])
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
		case ipv4.ICMPTypeEchoReply:
			logger.Debug("Received ICMP Echo Reply from", "peer", peer)
			if echo, ok := rm.Body.(*icmp.Echo); ok {
				if echo.ID == id && echo.Data[0] == 0xff {
					logger.Debug("Received valid ICMP Echo Reply with port request from", "peer", peer)
					return decodePort(echo.Data)
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
