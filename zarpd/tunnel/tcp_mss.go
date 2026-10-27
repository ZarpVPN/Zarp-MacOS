package tunnel

import "encoding/binary"

// clampTCPMSS bounds both TCP directions before their SYN reaches the other
// stack. Interface MTU stays IPv6-safe; QUIC framing still needs space inside
// each UDP datagram. Other packets, fragments and malformed options pass through.
func clampTCPMSS(packet []byte, maximumPacketSize int) bool {
	if maximumPacketSize <= 0 || len(packet) < 20 {
		return false
	}
	ipHeader, packetLength := 0, 0
	switch packet[0] >> 4 {
	case 4:
		ipHeader = int(packet[0]&15) * 4
		packetLength = int(binary.BigEndian.Uint16(packet[2:4]))
		if ipHeader < 20 || packetLength < ipHeader || packetLength > len(packet) || packet[9] != 6 || binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
			return false
		}
	case 6:
		if len(packet) < 40 {
			return false
		}
		packetLength = 40 + int(binary.BigEndian.Uint16(packet[4:6]))
		if packetLength <= 40 || packetLength > len(packet) {
			return false
		}
		ipHeader = 40
		next := packet[6]
		for count := 0; next != 6; count++ {
			if count >= 8 || ipHeader+2 > packetLength {
				return false
			}
			length := 0
			switch next {
			case 0, 43, 60:
				length = (int(packet[ipHeader+1]) + 1) * 8
			default:
				return false // Includes fragments, AH and encrypted payloads.
			}
			if length < 8 || ipHeader+length > packetLength {
				return false
			}
			next = packet[ipHeader]
			ipHeader += length
		}
	default:
		return false
	}
	if packetLength-ipHeader < 20 {
		return false
	}
	tcp := packet[ipHeader:packetLength]
	if tcp[13]&2 == 0 || tcp[13]&5 != 0 {
		return false
	}
	headerLength := int(tcp[12]>>4) * 4
	if headerLength < 20 || headerLength > len(tcp) {
		return false
	}
	mss := maximumPacketSize - ipHeader - 20
	if mss < 1 || mss > 65535 {
		return false
	}
	var positions [10]int
	count := 0
	for offset := 20; offset < headerLength; {
		kind := tcp[offset]
		if kind == 0 {
			break
		}
		if kind == 1 {
			offset++
			continue
		}
		if offset+2 > headerLength {
			return false
		}
		length := int(tcp[offset+1])
		if length < 2 || offset+length > headerLength {
			return false
		}
		if kind == 2 {
			if length != 4 {
				return false
			}
			if int(binary.BigEndian.Uint16(tcp[offset+2:offset+4])) > mss {
				positions[count] = offset + 2
				count++
			}
		}
		offset += length
	}
	if count == 0 {
		return false
	}
	// RFC 1624 adjustment preserves the original checksum residual, including
	// invalid input. An MSS option can start at an odd byte offset.
	sum := uint32(^binary.BigEndian.Uint16(tcp[16:18]))
	for _, position := range positions[:count] {
		old, newValue := binary.BigEndian.Uint16(tcp[position:position+2]), uint16(mss)
		binary.BigEndian.PutUint16(tcp[position:position+2], newValue)
		if position&1 != 0 {
			old, newValue = (old<<8)|(old>>8), (newValue<<8)|(newValue>>8)
		}
		sum += uint32(^old) + uint32(newValue)
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(tcp[16:18], ^uint16(sum))
	return true
}
