package network

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math/rand"
	"net"
	"strings"
	"time"
	"unsafe"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/crypt/engines"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

var cEngine engines.CryptoEngine

const IDSTRING = "SNAKE_SERVER_INFO_REQUEST"

var Protocols = []string{"tcp", "udp", "tls", "dtls", "quic", "kcp"}

const (
	seqProtoMask      uint16 = 0x0007
	ipv6FlowLabelMask uint32 = 0x000FFFFF
	ipv6FlowInfoCmsg         = 11
	ipv4HeaderLen            = 20
)

func protocolToCode(proto string) (uint16, bool) {
	for i, p := range Protocols {
		if strings.ToLower(proto) == p {
			return uint16(i), true
		}
	}
	return 0, false
}

func codeToProtocol(code uint16) string {
	idx := int(code & seqProtoMask)
	if idx < 0 || idx >= len(Protocols) {
		return ""
	}
	return Protocols[idx]
}

func encodeServerInfoToIPv4Header(port uint16, protocol string) (uint16, int, bool) {
	protoCode, ok := protocolToCode(protocol)
	if !ok {
		return 0, 0, false
	}
	// Reserve DSCP code 0 to distinguish server reply from a normal OS echo reply.
	dscpCode := int(protoCode) + 1
	return port, dscpCode << 2, true
}

func decodeServerInfoFromIPv4Header(header *ipv4.Header) (uint16, string, bool) {
	if header == nil {
		return 0, "", false
	}
	dscpCode := (header.TOS >> 2) & 0x3F
	if dscpCode == 0 {
		return 0, "", false
	}
	protocol := codeToProtocol(uint16(dscpCode - 1))
	if protocol == "" {
		return 0, "", false
	}
	port := uint16(header.ID)
	if port == 0 {
		return 0, "", false
	}
	return port, protocol, true
}

func encodeServerInfoToFlowLabel(port uint16, protocol string) (uint32, bool) {
	protoCode, ok := protocolToCode(protocol)
	if !ok {
		return 0, false
	}
	return (uint32(port) << 3) | uint32(protoCode), true
}

func decodeServerInfoFromFlowLabel(flowInfo uint32) (uint16, string, bool) {
	flowLabel := flowInfo & ipv6FlowLabelMask
	port := uint16(flowLabel >> 3)
	if port == 0 {
		return 0, "", false
	}
	protocolCode := uint16(flowLabel & uint32(seqProtoMask))
	protocol := codeToProtocol(protocolCode)
	if protocol == "" {
		return 0, "", false
	}
	return port, protocol, true
}

func setIPv6SockOptInt(conn *net.IPConn, opt int, value int) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var sockErr error
	if err := rawConn.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, opt, value)
	}); err != nil {
		return err
	}
	return sockErr
}

func marshalIPv6FlowInfo(flowInfo uint32) []byte {
	b := make([]byte, unix.CmsgSpace(4))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level = unix.IPPROTO_IPV6
	h.Type = ipv6FlowInfoCmsg
	h.SetLen(unix.CmsgLen(4))
	// Linux expects IPV6_FLOWINFO ancillary payload in network byte order.
	binary.BigEndian.PutUint32(b[unix.CmsgLen(0):unix.CmsgLen(0)+4], flowInfo&ipv6FlowLabelMask)
	return b
}

func parseIPv6AncillaryData(oob []byte) (net.IP, int, uint32, error) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, 0, 0, err
	}
	var dstIP net.IP
	var ifIndex int
	var flowInfo uint32
	for _, msg := range msgs {
		switch {
		case msg.Header.Level == unix.SOL_IPV6 && msg.Header.Type == unix.IPV6_PKTINFO && len(msg.Data) >= unix.SizeofInet6Pktinfo:
			pktInfo := *(*unix.Inet6Pktinfo)(unsafe.Pointer(&msg.Data[0]))
			dstIP = append(net.IP(nil), pktInfo.Addr[:]...)
			ifIndex = int(pktInfo.Ifindex)
		case msg.Header.Level == unix.IPPROTO_IPV6 && msg.Header.Type == ipv6FlowInfoCmsg && len(msg.Data) >= 4:
			flowInfo = binary.BigEndian.Uint32(msg.Data[:4])
		}
	}
	return dstIP, ifIndex, flowInfo & ipv6FlowLabelMask, nil
}

func buildIPv6ReplyOOB(dstIP net.IP, ifIndex int, flowLabel uint32) []byte {
	pktInfo := &unix.Inet6Pktinfo{Ifindex: uint32(ifIndex)}
	copy(pktInfo.Addr[:], dstIP.To16())
	oob := unix.PktInfo6(pktInfo)
	return append(oob, marshalIPv6FlowInfo(flowLabel)...)
}

func StartICMPListen(secret string) {
	secretBin := make([]byte, 32)
	sum256 := sha256.Sum256([]byte(secret))
	copy(secretBin, sum256[:])

	var err error
	cEngine, err = engines.NewEngineByName("aes", secretBin, 256, "gcm")
	if err != nil {
		configs.GetLogger("icmp").Fatal("Error initializing crypto engine", "error", err)
	}
	go func() {
		StartICMPCommonListen(true)
	}()
	go func() {
		StartICMPCommonListen(false)
	}()
}

func isOurPacket(data []byte) bool {
	logger := configs.GetLogger("icmp")
	buf, err := cEngine.Decrypt(data)
	if err != nil {
		logger.Debug("Error decrypting data", "error", err)
		return false
	}
	if len(buf) < len(IDSTRING) {
		logger.Debug("Decrypted ICMP data is too short", "len", len(buf))
		return false
	}
	logger.Trace("Decrypted ICMP data", "data", string(buf), "len", len(buf))
	return string(buf[:len(IDSTRING)]) == IDSTRING
}

func fillData(data []byte) []byte {
	buf := make([]byte, len(data))
	copy(buf, data)
	encBuf, err := cEngine.Encrypt(buf)
	if err != nil {
		configs.GetLogger("icmp").Fatal("Error encrypting data", "error", err)
	}
	return encBuf
}

func StartICMPCommonListen(isIPv4 bool) {
	if isIPv4 {
		startICMPv4Listen()
		return
	}
	startICMPv6Listen()
}

func startICMPv4Listen() {
	logger := configs.GetLogger("icmp")
	ipConn, err := net.ListenIP("ip4:icmp", &net.IPAddr{IP: net.IPv4zero})
	if err != nil {
		panic(err)
	}
	defer ipConn.Close()
	rawConn, err := ipv4.NewRawConn(ipConn)
	if err != nil {
		logger.Fatal("Error creating raw IPv4 connection", "error", err)
	}

	buf := make([]byte, 1500)
	for {
		header, payload, _, err := rawConn.ReadFrom(buf)
		if err != nil {
			logger.Fatal("Error reading ICMPv4 packet", "error", err)
		}
		msg, err := icmp.ParseMessage(ipv4.ICMPTypeEcho.Protocol(), payload)
		if err != nil {
			logger.Error("Error parsing ICMPv4 message", "error", err)
			continue
		}
		if msg.Type != ipv4.ICMPTypeEcho {
			continue
		}
		echo, ok := msg.Body.(*icmp.Echo)
		if !ok {
			logger.Error("Invalid ICMPv4 Echo message body")
			continue
		}
		if !isOurPacket(echo.Data) {
			logger.Trace("Ignore alien packet")
			continue
		}
		if header == nil || header.Src == nil || header.Dst == nil {
			logger.Error("Invalid IPv4 header in ICMP request")
			continue
		}
		srcIPv4 := header.Src.To4()
		dstIPv4 := header.Dst.To4()
		if srcIPv4 == nil || dstIPv4 == nil {
			logger.Error("Non-IPv4 addresses in ICMPv4 request header", "src", header.Src, "dst", header.Dst)
			continue
		}
		cfg := configs.GetConfig()
		ipID, tos, ok := encodeServerInfoToIPv4Header(cfg.LocalPort, cfg.Protocol)
		if !ok {
			logger.Error("Unsupported protocol for ICMPv4 discovery", "protocol", cfg.Protocol)
			continue
		}
		reply := &icmp.Message{
			Type: ipv4.ICMPTypeEchoReply,
			Code: 0,
			Body: &icmp.Echo{ID: echo.ID, Seq: echo.Seq, Data: echo.Data},
		}
		icmpBytes, err := reply.Marshal(nil)
		if err != nil {
			logger.Error("Error marshaling ICMPv4 message", "error", err)
			continue
		}
		replyHeader := &ipv4.Header{
			Version:  ipv4.Version,
			Len:      ipv4HeaderLen,
			TOS:      tos,
			TotalLen: ipv4HeaderLen + len(icmpBytes),
			ID:       int(ipID),
			FragOff:  0,
			TTL:      64,
			Protocol: 1,
			Src:      append(net.IP(nil), dstIPv4...),
			Dst:      append(net.IP(nil), srcIPv4...),
		}
		if err := rawConn.WriteTo(replyHeader, icmpBytes, nil); err != nil {
			logger.Error("Error sending ICMPv4 Echo Reply", "error", err, "src", replyHeader.Src, "dst", replyHeader.Dst, "ip_id", replyHeader.ID, "tos", replyHeader.TOS)
			continue
		}
		logger.Debug("Sent ICMPv4 Echo Reply", "dst", replyHeader.Dst, "ip_id", ipID, "tos", tos)
	}
}

func startICMPv6Listen() {
	logger := configs.GetLogger("icmp")
	ipConn, err := net.ListenIP("ip6:ipv6-icmp", &net.IPAddr{IP: net.IPv6zero})
	if err != nil {
		panic(err)
	}
	defer ipConn.Close()

	if err := setIPv6SockOptInt(ipConn, unix.IPV6_RECVPKTINFO, 1); err != nil {
		logger.Fatal("Error enabling IPv6 pktinfo", "error", err)
	}
	if err := setIPv6SockOptInt(ipConn, ipv6FlowInfoCmsg, 1); err != nil {
		logger.Fatal("Error enabling IPv6 flowinfo", "error", err)
	}

	buf := make([]byte, 1500)
	oob := make([]byte, 256)
	for {
		n, oobn, _, peer, err := ipConn.ReadMsgIP(buf, oob)
		if err != nil {
			logger.Fatal("Error reading ICMPv6 packet", "error", err)
		}
		dstIP, ifIndex, _, err := parseIPv6AncillaryData(oob[:oobn])
		if err != nil {
			logger.Error("Error parsing ICMPv6 ancillary data", "error", err)
			continue
		}
		msg, err := icmp.ParseMessage(ipv6.ICMPTypeEchoRequest.Protocol(), buf[:n])
		if err != nil {
			logger.Error("Error parsing ICMPv6 message", "error", err)
			continue
		}
		if msg.Type != ipv6.ICMPTypeEchoRequest {
			continue
		}
		echo, ok := msg.Body.(*icmp.Echo)
		if !ok {
			logger.Error("Invalid ICMPv6 Echo message body")
			continue
		}
		if !isOurPacket(echo.Data) {
			logger.Trace("Ignore alien packet")
			continue
		}
		cfg := configs.GetConfig()
		flowLabel, ok := encodeServerInfoToFlowLabel(cfg.LocalPort, cfg.Protocol)
		if !ok {
			logger.Error("Unsupported protocol for ICMPv6 discovery", "protocol", cfg.Protocol)
			continue
		}
		peerIP := peer
		if len(dstIP) == 0 {
			logger.Error("No destination IP from IPv6 pktinfo", "peer", peer)
			continue
		}
		reply := &icmp.Message{
			Type: ipv6.ICMPTypeEchoReply,
			Code: 0,
			Body: &icmp.Echo{
				ID:   echo.ID,
				Seq:  echo.Seq,
				Data: echo.Data,
			},
		}
		replyBytes, err := reply.Marshal(icmp.IPv6PseudoHeader(dstIP, peerIP.IP))
		if err != nil {
			logger.Error("Error marshaling ICMPv6 message", "error", err)
			continue
		}
		oobReply := buildIPv6ReplyOOB(dstIP, ifIndex, flowLabel)
		if _, _, err := ipConn.WriteMsgIP(replyBytes, oobReply, peerIP); err != nil {
			logger.Error("Error sending ICMPv6 Echo Reply", "error", err)
			continue
		}
		logger.Debug("Sent ICMPv6 Echo Reply to", "peer", peer, "flow_label", flowLabel)
	}
}

func GetICMPPort(addr net.IPAddr, secret string) (uint16, string) {
	if addr.IP.To4() != nil {
		return getICMPv4Port(addr, secret)
	}
	return getICMPv6Port(addr, secret)
}

func getICMPv4Port(addr net.IPAddr, secret string) (uint16, string) {
	secretBin := make([]byte, 32)
	sum256 := sha256.Sum256([]byte(secret))
	copy(secretBin, sum256[:])

	logger := configs.GetLogger("icmp")
	logger.Debug("Asking port from server via ICMPv4", "peer", addr)
	var err error
	cEngine, err = engines.NewEngineByName("aes", secretBin, 256, "gcm")
	if err != nil {
		logger.Fatal("Error initializing crypto engine", "error", err)
	}

	icmpConn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		logger.Fatal("Error listening for ICMP packets", "error", err)
	}
	defer icmpConn.Close()
	ipConn, err := net.ListenIP("ip4:icmp", &net.IPAddr{IP: net.IPv4zero})
	if err != nil {
		logger.Fatal("Error listening for ICMPv4 packets", "error", err)
	}
	defer ipConn.Close()
	rawConn, err := ipv4.NewRawConn(ipConn)
	if err != nil {
		logger.Fatal("Error creating raw IPv4 connection", "error", err)
	}

	data := fillData([]byte(IDSTRING))
	id := rand.Intn(65535)
	seq := rand.Intn(65535)
	request := &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{ID: id, Seq: seq, Data: data},
	}
	requestBytes, err := request.Marshal(nil)
	if err != nil {
		logger.Fatal("Marshaling error", "error", err)
	}
	if _, err := icmpConn.WriteTo(requestBytes, &addr); err != nil {
		logger.Fatal("Error sending ICMPv4 Echo", "error", err)
	}
	logger.Debug("Sent ICMPv4 Echo to", "peer", addr.String())

	reply := make([]byte, 1500)
	if err := rawConn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		logger.Fatal("Error setting ICMPv4 read deadline", "error", err)
	}

	i := 0
	for {
		header, payload, _, err := rawConn.ReadFrom(reply)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				logger.Debug("ICMPv4 read timeout while waiting for Echo Reply", "peer", addr)
				return 0, ""
			}
			logger.Error("Error receiving ICMPv4 Echo Reply", "error", err)
			return 0, ""
		}
		rm, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), payload)
		if err != nil {
			logger.Debug("Error parsing ICMPv4 message", "error", err)
			continue
		}
		i++
		if i > 10 {
			logger.Debug("Too many ICMPv4 messages received without valid Echo Reply, giving up", "peer", addr)
			break
		}
		if rm.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		echo, ok := rm.Body.(*icmp.Echo)
		if !ok {
			continue
		}
		if !bytes.Equal(echo.Data, data) {
			logger.Debug("Received ICMPv4 Echo Reply with mismatched payload", "src", header.Src)
			continue
		}
		port, protocol, ok := decodeServerInfoFromIPv4Header(header)
		if !ok {
			if echo.ID == id && echo.Seq == seq {
				logger.Debug("Received ICMPv4 Echo Reply from OS. Ignored.", "src", header.Src)
			}
			continue
		}
		logger.Debug("Received server info", "src", header.Src, "port", port, "protocol", protocol, "request_id", id, "ip_id", header.ID, "tos", header.TOS)
		return port, protocol
	}
	return 0, ""
}

func getICMPv6Port(addr net.IPAddr, secret string) (uint16, string) {
	secretBin := make([]byte, 32)
	sum256 := sha256.Sum256([]byte(secret))
	copy(secretBin, sum256[:])

	logger := configs.GetLogger("icmp")
	logger.Debug("Asking port from server via ICMPv6", "peer", addr)
	var err error
	cEngine, err = engines.NewEngineByName("aes", secretBin, 256, "gcm")
	if err != nil {
		logger.Fatal("Error initializing crypto engine", "error", err)
	}

	ipConn, err := net.ListenIP("ip6:ipv6-icmp", &net.IPAddr{IP: net.IPv6zero})
	if err != nil {
		logger.Fatal("Error listening for ICMPv6 packets", "error", err)
	}
	defer ipConn.Close()

	if err := setIPv6SockOptInt(ipConn, ipv6FlowInfoCmsg, 1); err != nil {
		logger.Fatal("Error enabling IPv6 flowinfo", "error", err)
	}

	data := fillData([]byte(IDSTRING))
	id := rand.Intn(65535)
	seq := rand.Intn(65535)
	icmpMessage := &icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest,
		Code: 0,
		Body: &icmp.Echo{
			ID:   id,
			Seq:  seq,
			Data: data,
		},
	}
	icmpBytes, err := icmpMessage.Marshal(nil)
	if err != nil {
		logger.Fatal("Marshaling error", "error", err)
	}
	if _, _, err := ipConn.WriteMsgIP(icmpBytes, nil, &addr); err != nil {
		logger.Fatal("Error sending ICMPv6 Echo", "error", err)
	}
	logger.Debug("Sent ICMPv6 Echo to", "peer", addr.String())

	reply := make([]byte, 1500)
	oob := make([]byte, 256)
	if err := ipConn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		logger.Fatal("Error setting ICMPv6 read deadline", "error", err)
	}

	i := 0
	for {
		n, oobn, _, peer, err := ipConn.ReadMsgIP(reply, oob)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				logger.Debug("ICMPv6 read timeout while waiting for Echo Reply", "peer", addr)
				return 0, ""
			}
			logger.Error("Error receiving ICMPv6 Echo Reply", "error", err)
			return 0, ""
		}
		rm, err := icmp.ParseMessage(ipv6.ICMPTypeEchoReply.Protocol(), reply[:n])
		if err != nil {
			logger.Debug("Error parsing ICMPv6 message", "error", err)
			continue
		}
		i++
		if i > 10 {
			logger.Debug("Too many ICMPv6 messages received without valid Echo Reply, giving up", "peer", addr)
			break
		}
		if rm.Type != ipv6.ICMPTypeEchoReply {
			continue
		}
		echo, ok := rm.Body.(*icmp.Echo)
		if !ok {
			continue
		}
		if !bytes.Equal(echo.Data, data) {
			logger.Debug("Received ICMPv6 Echo Reply with mismatched payload from", "peer", peer)
			continue
		}
		_, _, flowInfo, err := parseIPv6AncillaryData(oob[:oobn])
		if err != nil {
			logger.Debug("Failed to parse ICMPv6 ancillary data", "error", err)
			continue
		}
		port, protocol, ok := decodeServerInfoFromFlowLabel(flowInfo)
		if !ok {
			logger.Debug("Received ICMPv6 Echo Reply without valid flow label encoding", "peer", peer, "flow_info", flowInfo)
			continue
		}
		if echo.ID == id && echo.Seq == seq && flowInfo == 0 {
			logger.Debug("Received ICMPv6 Echo Reply from OS. Ignored.", "peer", peer)
			continue
		}
		logger.Debug("Received server info", "peer", peer, "port", port, "protocol", protocol, "request_id", id, "flow_info", flowInfo)
		return port, protocol
	}
	return 0, ""
}
