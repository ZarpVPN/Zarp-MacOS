package main

import (
	"encoding/binary"
	"testing"
)

func packetFixture(protocol byte, source, destination uint16, payload []byte) []byte {
	transport := 8
	if protocol == 6 {
		transport = 20
	}
	data := make([]byte, 4+20+transport+len(payload))
	binary.LittleEndian.PutUint32(data, 2)
	ip := data[4:]
	ip[0] = 0x45
	ip[9] = protocol
	binary.BigEndian.PutUint16(ip[2:], uint16(len(ip)))
	copy(ip[12:], []byte{127, 0, 0, 1})
	copy(ip[16:], []byte{127, 0, 0, 1})
	body := ip[20:]
	binary.BigEndian.PutUint16(body, source)
	binary.BigEndian.PutUint16(body[2:], destination)
	if protocol == 6 {
		body[12] = 0x50
		binary.BigEndian.PutUint32(body[4:], 1000)
	} else {
		binary.BigEndian.PutUint16(body[4:], uint16(len(body)))
	}
	copy(body[transport:], payload)
	return data
}

func TestNativeFilterAcceptsOnlyReservedLoopbackProtocolPorts(t *testing.T) {
	for _, test := range []struct {
		protocol            byte
		source, destination uint16
		match               bool
	}{
		{6, 40000, 41000, true}, {6, 41000, 40000, true}, {17, 40000, 42000, true}, {17, 42000, 40000, true},
		{6, 40000, 42000, false}, {17, 40000, 41000, false}, {6, 40000, 43000, false}, {1, 40000, 41000, false},
	} {
		data := packetFixture(test.protocol, test.source, test.destination, []byte("private-test"))
		if nativeFilterMatches(data, 41000, 42000) != test.match {
			t.Fatal("native filter accepted unrelated port/protocol or rejected owned tuple")
		}
		data[16] = 10
		if nativeFilterMatches(data, 41000, 42000) {
			t.Fatal("native filter accepted non-loopback source")
		}
		data[16] = 127
		data[20] = 10
		if nativeFilterMatches(data, 41000, 42000) {
			t.Fatal("native filter accepted non-loopback destination")
		}
		data[20] = 127
		data[0] = 30
		if nativeFilterMatches(data, 41000, 42000) {
			t.Fatal("native filter accepted another address family")
		}
	}
	for _, data := range [][]byte{nil, {2, 0, 0, 0}, packetFixture(6, 40000, 41000, nil)[:24]} {
		if nativeFilterMatches(data, 41000, 42000) {
			t.Fatal("native filter accepted truncated packet")
		}
	}
}

func TestIPv4OptionsPreserveReservedPortFilterAndPayloadDecode(t *testing.T) {
	for _, protocol := range []byte{6, 17} {
		data := packetFixture(protocol, 40000, 41000, []byte("private-test"))
		options := append(append(append([]byte(nil), data[:24]...), 1, 1, 1, 1), data[24:]...)
		options[4] = 0x46
		binary.BigEndian.PutUint16(options[6:], uint16(len(options)-4))
		if !nativeFilterMatches(options, 41000, 41000) {
			t.Fatal("IPv4 options mislocated owned transport port")
		}
		packet, ok := decodeWirePacket(options)
		if !ok || packet.source != 40000 || packet.destination != 41000 || string(packet.payload) != "private-test" {
			t.Fatal("IPv4 options changed decoded tuple/payload")
		}
	}
}

func TestDecoderRefusesForeignMalformedFragmentedAndTruncatedPackets(t *testing.T) {
	for _, protocol := range []byte{6, 17} {
		data := packetFixture(protocol, 40000, 41000, []byte("private-test"))
		packet, ok := decodeWirePacket(data)
		if !ok || packet.source != 40000 || packet.destination != 41000 || string(packet.payload) != "private-test" {
			t.Fatal("valid packet lost tuple/payload")
		}
		for _, mutate := range []func([]byte){
			func(b []byte) { b[0] = 30 }, func(b []byte) { b[4] = 0x44 }, func(b []byte) { b[16] = 10 },
			func(b []byte) { b[10] = 0x20 }, func(b []byte) { b[7] = 255 }, func(b []byte) { b[13] = 1 },
		} {
			changed := append([]byte(nil), data...)
			mutate(changed)
			if _, ok := decodeWirePacket(changed); ok {
				t.Fatal("foreign or malformed capture decoded")
			}
		}
		if _, ok := decodeWirePacket(data[:len(data)-1]); ok {
			t.Fatal("truncated packet decoded")
		}
	}
}

func TestTCPProofRequiresExactPacketBoundariesBytesOrderAndFreshTuple(t *testing.T) {
	expected := tcpExpectation{port: 40000, chunks: []int{1, 3, 4}, wire: []byte("abcdefgh")}
	good := []wirePacket{{protocol: 6, source: 40000, destination: 41000, sequence: 100, payload: []byte("a")},
		{protocol: 6, source: 40000, destination: 41000, sequence: 101, payload: []byte("bcd")},
		{protocol: 6, source: 40000, destination: 41000, sequence: 104, payload: []byte("efgh")}}
	if _, ok := verifyTCPPackets(good, 41000, expected); !ok {
		t.Fatal("exact captured split refused")
	}
	for _, changed := range [][]wirePacket{
		{{protocol: 6, source: 40000, destination: 41000, sequence: 100, payload: []byte("abcdefgh")}},
		{good[1], good[0], good[2]}, good[:2],
		{good[0], good[1], {protocol: 6, source: 40000, destination: 41000, sequence: 104, payload: []byte("xxxx")}},
		{good[0], good[1], {protocol: 6, source: 40001, destination: 41000, sequence: 104, payload: []byte("efgh")}},
	} {
		if _, ok := verifyTCPPackets(changed, 41000, expected); ok {
			t.Fatal("coalesced, wrong or incomplete traffic certified packet split")
		}
	}
}

func TestUDPProofDoesNotCollapseRepeatedFakeOrAcceptOtherTuple(t *testing.T) {
	fake, real := []byte("fake"), []byte("real")
	first := wirePacket{protocol: 17, source: 40000, destination: 42000, payload: fake}
	second := wirePacket{protocol: 17, source: 40000, destination: 42000, payload: real}
	if !verifyUDPPackets([]wirePacket{first, second}, 42000, 40000, fake, real) {
		t.Fatal("same-tuple fake-first datagrams refused")
	}
	for _, packets := range [][]wirePacket{{second, first}, {first, first, second}, {first},
		{first, {protocol: 17, source: 40001, destination: 42000, payload: real}}} {
		if verifyUDPPackets(packets, 42000, 40000, fake, real) {
			t.Fatal("repeated, reordered or different-tuple fake certified")
		}
	}
}

func ipv6PacketFixture(protocol byte, source, destination uint16, payload []byte) []byte {
	v4 := packetFixture(protocol, source, destination, payload)
	data := make([]byte, 4+40+len(v4)-24)
	binary.LittleEndian.PutUint32(data, 30)
	ip := data[4:]
	ip[0], ip[6], ip[23], ip[39] = 0x60, protocol, 1, 1
	binary.BigEndian.PutUint16(ip[4:], uint16(len(ip)-40))
	copy(ip[40:], v4[24:])
	return data
}

func TestIPv6FilterMatchesOnlyCompleteLoopbackAddressesAndReservedPorts(t *testing.T) {
	for _, test := range []struct {
		protocol            byte
		source, destination uint16
		match               bool
	}{
		{6, 40000, 41000, true}, {6, 41000, 40000, true}, {17, 40000, 42000, true}, {17, 42000, 40000, true},
		{6, 40000, 42000, false}, {17, 40000, 41000, false}, {6, 40000, 43000, false},
		{44, 40000, 41000, false}, {0, 40000, 41000, false}, {60, 40000, 41000, false},
	} {
		data := ipv6PacketFixture(test.protocol, test.source, test.destination, []byte("private-v6"))
		if nativeFilterMatchesFamily(data, 41000, 42000, true) != test.match {
			t.Fatal("IPv6 filter accepted unrelated transport or rejected owned tuple")
		}
		if nativeFilterMatches(data, 41000, 42000) {
			t.Fatal("IPv4 filter accepted IPv6")
		}
		for offset := 12; offset < 44; offset++ {
			changed := append([]byte(nil), data...)
			changed[offset] ^= 2
			if nativeFilterMatchesFamily(changed, 41000, 42000, true) {
				t.Fatal("IPv6 filter accepted foreign address byte", offset)
			}
		}
		for _, length := range []int{0, 3, 4, 43, 47} {
			if nativeFilterMatchesFamily(data[:length], 41000, 42000, true) {
				t.Fatal("truncated IPv6 filter input accepted")
			}
		}
	}
	if nativeFilterMatchesFamily(packetFixture(6, 40000, 41000, nil), 41000, 42000, true) {
		t.Fatal("IPv6 filter accepted IPv4")
	}
}

func TestIPv6DecoderRejectsExtensionsFragmentsForeignAndMalformedFrames(t *testing.T) {
	for _, protocol := range []byte{6, 17} {
		data := ipv6PacketFixture(protocol, 40000, 41000, []byte("private-v6"))
		packet, ok := decodeWirePacket(data)
		if !ok || !packet.ipv6 || packet.source != 40000 || packet.destination != 41000 || string(packet.payload) != "private-v6" {
			t.Fatal("IPv6 packet lost its family, tuple or bytes")
		}
		for _, mutate := range []func([]byte){
			func(b []byte) { b[0] = 2 }, func(b []byte) { b[4] = 0x40 },
			func(b []byte) { b[8], b[9] = 0, 0 }, func(b []byte) { b[8], b[9] = 255, 255 },
			func(b []byte) { b[10] = 44 }, func(b []byte) { b[10] = 0 }, func(b []byte) { b[10] = 60 },
			func(b []byte) { b[12] = 1 }, func(b []byte) { b[43] = 2 },
			func(b []byte) {
				if protocol == 6 {
					b[56] = 0x40
				} else {
					b[49]--
				}
			},
		} {
			changed := append([]byte(nil), data...)
			mutate(changed)
			if _, ok := decodeWirePacket(changed); ok {
				t.Fatal("malformed IPv6 decoded")
			}
		}
		for length := 0; length < len(data); length++ {
			if _, ok := decodeWirePacket(data[:length]); ok {
				t.Fatal("truncated IPv6 decoded")
			}
		}
	}
}

func TestIPv6DecodedPacketsUseExactTCPAndUDPProof(t *testing.T) {
	expected := tcpExpectation{port: 40000, chunks: []int{1, 3, 4}, wire: []byte("abcdefgh")}
	var packets []wirePacket
	sequence := uint32(100)
	for _, payload := range [][]byte{[]byte("a"), []byte("bcd"), []byte("efgh")} {
		data := ipv6PacketFixture(6, 40000, 41000, payload)
		binary.BigEndian.PutUint32(data[48:], sequence)
		packet, ok := decodeWirePacket(data)
		if !ok {
			t.Fatal("fixture decode")
		}
		packets = append(packets, packet)
		sequence += uint32(len(payload))
	}
	if _, ok := verifyTCPPackets(packets, 41000, expected); !ok {
		t.Fatal("exact IPv6 TCP proof refused")
	}
	var udp []wirePacket
	for _, payload := range [][]byte{[]byte("fake"), []byte("real")} {
		packet, ok := decodeWirePacket(ipv6PacketFixture(17, 40000, 42000, payload))
		if !ok {
			t.Fatal("fixture decode")
		}
		udp = append(udp, packet)
	}
	if !verifyUDPPackets(udp, 42000, 40000, []byte("fake"), []byte("real")) {
		t.Fatal("IPv6 UDP proof refused")
	}
	if verifyUDPPackets([]wirePacket{udp[0], udp[0], udp[1]}, 42000, 40000, []byte("fake"), []byte("real")) {
		t.Fatal("IPv6 duplicate certified")
	}
}

func TestUDPHopLimitProofRequiresHeaderChangeAndRestoredRealTuple(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		var packets []wirePacket
		for i, payload := range [][]byte{[]byte("fake"), []byte("real")} {
			data := packetFixture(17, 40000, 42000, payload)
			offset := 12
			if ipv6 {
				data = ipv6PacketFixture(17, 40000, 42000, payload)
				offset = 11
			}
			data[offset] = 1
			if i == 1 {
				data[offset] = 73
			}
			packet, ok := decodeWirePacket(data)
			if !ok {
				t.Fatal("fixture decode")
			}
			packets = append(packets, packet)
		}
		if !verifyUDPHopLimitPackets(packets, 42000, 40000, []byte("fake"), []byte("real")) {
			t.Fatal("header fake/real proof refused")
		}
		for _, limits := range [][2]byte{{73, 73}, {1, 1}, {0, 73}, {73, 1}, {1, 0}} {
			changed := append([]wirePacket(nil), packets...)
			changed[0].hopLimit, changed[1].hopLimit = limits[0], limits[1]
			if verifyUDPHopLimitPackets(changed, 42000, 40000, []byte("fake"), []byte("real")) {
				t.Fatal("wrong or unrestored packet limits certified")
			}
		}
		if verifyUDPHopLimitPackets([]wirePacket{packets[1], packets[0]}, 42000, 40000, []byte("fake"), []byte("real")) {
			t.Fatal("reordered hop-limit proof accepted")
		}
	}
}
