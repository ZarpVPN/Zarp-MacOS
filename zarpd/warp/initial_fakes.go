package warp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/quic-go/quic-go"
	"golang.org/x/net/ipv4"
)

// FakeReport contains counts only. Connection IDs and packet contents stay out
// of application logs.
type FakeReport struct {
	Flight, Packets, Bytes int
}

// initialFakeConn preserves quic-go's OOB socket interface. In particular, it
// keeps interface binding, packet info, ECN and path MTU support on the original
// socket. A new Initial destination CID can follow Retry or HelloRetryRequest;
// each flight must receive the strategy before its first real packet.
type initialFakeConn struct {
	*net.UDPConn
	endpoint  *net.UDPAddr
	steps     []FakeStep
	onApplied func(FakeReport)
	writeMu   sync.Mutex
	flights   map[string]bool
	batch     *ipv4.PacketConn
	stats     *quicCounters
}

var _ quic.OOBCapablePacketConn = (*initialFakeConn)(nil)

const maxInitialFakeFlights = 4

func initialDestinationCID(packet []byte) (string, bool) {
	if len(packet) < 7 || packet[0]&0xc0 != 0xc0 {
		return "", false
	}
	version := binary.BigEndian.Uint32(packet[1:5])
	typeBits := (packet[0] >> 4) & 3
	if !((version == 1 && typeBits == 0) || (version == 0x6b3343cf && typeBits == 1)) {
		return "", false
	}
	length := int(packet[5])
	if length == 0 || length > 20 || 6+length > len(packet) {
		return "", false
	}
	return string(packet[6 : 6+length]), true
}

func (c *initialFakeConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (int, int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if id, initial := initialDestinationCID(b); len(c.steps) > 0 && initial && !c.flights[id] {
		if addr == nil || !addr.IP.Equal(c.endpoint.IP) || addr.Port != c.endpoint.Port || addr.Zone != c.endpoint.Zone {
			return 0, 0, atDialPhase("outer_strategy", errors.New("QUIC Initial changed strategy endpoint"))
		}
		if len(c.flights) >= maxInitialFakeFlights {
			return 0, 0, atDialPhase("outer_strategy", errors.New("QUIC Initial strategy flight limit exceeded"))
		}
		packets, size, err := SendFakes(c.UDPConn, addr, c.steps, nil)
		if err != nil {
			return 0, 0, atDialPhase("outer_strategy", fmt.Errorf("send handshake fakes: %w", err))
		}
		c.flights[id] = true
		if c.onApplied != nil {
			c.onApplied(FakeReport{Flight: len(c.flights), Packets: packets, Bytes: size})
		}
	}
	n, oobn, err := c.UDPConn.WriteMsgUDP(b, oob, addr)
	if n > 0 {
		c.stats.packet(true, n, b[0]&0x80 != 0, true)
	}
	return n, oobn, err
}

func (c *initialFakeConn) received(data []byte, n int, addr net.Addr) {
	if n <= 0 || len(data) == 0 {
		return
	}
	peer, ok := addr.(*net.UDPAddr)
	expected := ok && peer.IP.Equal(c.endpoint.IP) && peer.Port == c.endpoint.Port && peer.Zone == c.endpoint.Zone
	c.stats.packet(false, n, data[0]&0x80 != 0, expected)
}

// Preserve quic-go's batch/OOB read path while sampling packet sizes. Decoys
// use the underlying socket directly and do not count as real QUIC sends.
func (c *initialFakeConn) ReadBatch(messages []ipv4.Message, flags int) (int, error) {
	n, err := c.batch.ReadBatch(messages, flags)
	for i := 0; i < n && i < len(messages); i++ {
		msg := messages[i]
		if len(msg.Buffers) > 0 {
			c.received(msg.Buffers[0], msg.N, msg.Addr)
		}
	}
	return n, err
}

func (c *initialFakeConn) ReadMsgUDP(b, oob []byte) (int, int, int, *net.UDPAddr, error) {
	n, oobn, flags, addr, err := c.UDPConn.ReadMsgUDP(b, oob)
	c.received(b, n, addr)
	return n, oobn, flags, addr, err
}

func (c *initialFakeConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	udp, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("QUIC strategy requires a UDP address")
	}
	n, _, err := c.WriteMsgUDP(b, nil, udp)
	return n, err
}
