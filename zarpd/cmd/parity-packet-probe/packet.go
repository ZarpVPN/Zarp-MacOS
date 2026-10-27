package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
)

type wirePacket struct {
	ipv6                bool
	hopLimit            byte
	protocol            byte
	source, destination uint16
	sequence            uint32
	payload             []byte
}

func decodeWirePacket(data []byte) (wirePacket, bool) {
	if len(data) < 4 {
		return wirePacket{}, false
	}
	ip := data[4:]
	var transport []byte
	var protocol, hopLimit byte
	ipv6 := false
	switch binary.LittleEndian.Uint32(data[:4]) {
	case 2: // Darwin AF_INET, DLT_NULL host endian on arm64.
		if len(ip) < 20 {
			return wirePacket{}, false
		}
		header := int(ip[0]&15) * 4
		total := int(binary.BigEndian.Uint16(ip[2:4]))
		if ip[0]>>4 != 4 || header < 20 || total < header || total > len(ip) || binary.BigEndian.Uint16(ip[6:8])&0x3fff != 0 ||
			!bytes.Equal(ip[12:16], []byte{127, 0, 0, 1}) || !bytes.Equal(ip[16:20], []byte{127, 0, 0, 1}) {
			return wirePacket{}, false
		}
		transport, protocol, hopLimit = ip[header:total], ip[9], ip[8]
	case 30: // Darwin AF_INET6. Fixed fixtures never use extension headers.
		if len(ip) < 40 {
			return wirePacket{}, false
		}
		length := int(binary.BigEndian.Uint16(ip[4:6]))
		loopback := [16]byte{15: 1}
		if ip[0]>>4 != 6 || length == 0 || length > len(ip)-40 ||
			!bytes.Equal(ip[8:24], loopback[:]) || !bytes.Equal(ip[24:40], loopback[:]) {
			return wirePacket{}, false
		}
		transport, protocol, ipv6, hopLimit = ip[40:40+length], ip[6], true, ip[7]
	default:
		return wirePacket{}, false
	}
	if len(transport) < 8 {
		return wirePacket{}, false
	}
	packet := wirePacket{ipv6: ipv6, hopLimit: hopLimit, protocol: protocol, source: binary.BigEndian.Uint16(transport), destination: binary.BigEndian.Uint16(transport[2:])}
	switch packet.protocol {
	case 6:
		if len(transport) < 20 {
			return wirePacket{}, false
		}
		skip := int(transport[12]>>4) * 4
		if skip < 20 || skip > len(transport) {
			return wirePacket{}, false
		}
		packet.sequence = binary.BigEndian.Uint32(transport[4:])
		packet.payload = append([]byte(nil), transport[skip:]...)
	case 17:
		length := int(binary.BigEndian.Uint16(transport[4:]))
		if length < 8 || length != len(transport) {
			return wirePacket{}, false
		}
		packet.payload = append([]byte(nil), transport[8:]...)
	default:
		return wirePacket{}, false
	}
	return packet, true
}

type tcpExpectation struct {
	port   uint16
	chunks []int
	wire   []byte
}

func verifyTCPPackets(packets []wirePacket, target uint16, expected tcpExpectation) ([]int, bool) {
	var segments []wirePacket
	seen := map[uint32][]byte{}
	for _, packet := range packets {
		if packet.protocol != 6 || packet.destination != target || packet.source != expected.port || len(packet.payload) == 0 {
			continue
		}
		if previous, ok := seen[packet.sequence]; ok {
			if !bytes.Equal(previous, packet.payload) {
				return nil, false
			}
			continue // Identical TCP retransmissions do not create a new boundary.
		}
		seen[packet.sequence] = packet.payload
		segments = append(segments, packet)
	}
	if len(segments) == 0 {
		return nil, false
	}
	var joined []byte
	var lengths []int
	sequence := segments[0].sequence
	for _, packet := range segments {
		if len(joined) >= len(expected.wire) {
			break
		}
		if packet.sequence != sequence {
			return lengths, false
		}
		joined = append(joined, packet.payload...)
		lengths = append(lengths, len(packet.payload))
		sequence += uint32(len(packet.payload))
	}
	if len(lengths) != len(expected.chunks) || sha256.Sum256(joined) != sha256.Sum256(expected.wire) {
		return lengths, false
	}
	for i, value := range lengths {
		if value != expected.chunks[i] {
			return lengths, false
		}
	}
	return lengths, true
}

func verifyUDPPackets(packets []wirePacket, target, source uint16, fake, real []byte) bool {
	var payloads [][]byte
	for _, packet := range packets {
		if packet.protocol != 17 || packet.destination != target || packet.source != source {
			continue
		}
		// XNU lo0 exposes its output tap. Never collapse a repeated datagram
		// into an apparent single fake.
		payloads = append(payloads, packet.payload)
	}
	return len(payloads) == 2 && bytes.Equal(payloads[0], fake) && bytes.Equal(payloads[1], real)
}

// Packet headers, not socket-option counters, must show the temporary fake
// limit and a restored real datagram on the identical outer tuple.
func verifyUDPHopLimitPackets(packets []wirePacket, target, source uint16, fake, real []byte) bool {
	if !verifyUDPPackets(packets, target, source, fake, real) {
		return false
	}
	limits := udpPacketHopLimits(packets, target, source)
	return len(limits) == 2 && limits[0] == 1 && limits[1] > 1
}

func udpPacketHopLimits(packets []wirePacket, target, source uint16) []int {
	var limits []int
	for _, p := range packets {
		if p.protocol == 17 && p.destination == target && p.source == source {
			limits = append(limits, int(p.hopLimit))
		}
	}
	return limits
}
