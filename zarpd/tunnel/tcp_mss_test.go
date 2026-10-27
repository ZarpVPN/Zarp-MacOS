package tunnel

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func checksumWords(data []byte) uint32 {
	var result uint32
	for i := 0; i < len(data); i += 2 {
		word := uint16(data[i]) << 8
		if i+1 < len(data) {
			word |= uint16(data[i+1])
		}
		result += uint32(word)
	}
	return result
}

func tcpResidual(packet []byte, offset int) uint16 {
	tcp := packet[offset:]
	var sum uint32
	if packet[0]>>4 == 4 {
		sum = checksumWords(packet[12:20])
	} else {
		sum = checksumWords(packet[8:40])
	}
	sum += uint32(len(tcp)) + 6 + checksumWords(tcp)
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func mssPacket(v6, extension bool, options []byte) ([]byte, int) {
	offset := 20
	if v6 {
		offset = 40
		if extension {
			offset += 8
		}
	}
	packet := make([]byte, offset+20+len(options)+3)
	if v6 {
		packet[0], packet[6], packet[7] = 0x60, 6, 64
		binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-40))
		packet[8], packet[24] = 0x20, 0x20
		packet[23], packet[39] = 1, 2
		if extension {
			packet[6] = 0
			packet[40] = 6
		}
	} else {
		packet[0], packet[8], packet[9] = 0x45, 64, 6
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		copy(packet[12:20], []byte{192, 0, 2, 1, 198, 51, 100, 2})
	}
	tcp := packet[offset:]
	binary.BigEndian.PutUint16(tcp[:2], 12345)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	tcp[12], tcp[13] = byte((20+len(options))/4)<<4, 2
	copy(tcp[20:], options)
	copy(tcp[20+len(options):], []byte{3, 4, 5})
	binary.BigEndian.PutUint16(tcp[16:18], tcpResidual(packet, offset))
	return packet, offset
}

func TestMSSClampPreservesChecksumsAndOnlyLowersNegotiatedSize(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for _, extension := range []bool{false, true} {
			if extension && !v6 {
				continue
			}
			for _, options := range [][]byte{{2, 4, 5, 180}, {1, 2, 4, 5, 180, 1, 1, 0}, {2, 4, 5, 180, 2, 4, 6, 64}} {
				for _, corrupt := range []bool{false, true} {
					packet, offset := mssPacket(v6, extension, options)
					if corrupt {
						packet[offset+16] ^= 1
					}
					before := tcpResidual(packet, offset)
					originalHeader := append([]byte(nil), packet[:offset]...)
					if !clampTCPMSS(packet, 1200) {
						t.Fatal("valid SYN was not clamped")
					}
					if after := tcpResidual(packet, offset); after != before {
						t.Fatalf("checksum residual changed: %x to %x", before, after)
					}
					if !bytes.Equal(originalHeader, packet[:offset]) {
						t.Fatal("IP header changed")
					}
					for i, option := range options {
						if option == 2 && i+3 < len(options) && options[i+1] == 4 {
							if got := int(binary.BigEndian.Uint16(packet[offset+20+i+2 : offset+20+i+4])); got != 1200-offset-20 {
								t.Fatalf("MSS = %d", got)
							}
						}
					}
					unchanged := append([]byte(nil), packet...)
					if clampTCPMSS(packet, 1400) || !bytes.Equal(packet, unchanged) {
						t.Fatal("smaller MSS was increased or rewritten")
					}
				}
			}
		}
	}
}

func TestMSSClampLeavesTruncatedMalformedAndOtherTrafficAlone(t *testing.T) {
	packet, offset := mssPacket(false, false, []byte{2, 4, 5, 180})
	for length := 0; length < len(packet); length++ {
		truncated := append([]byte(nil), packet[:length]...)
		before := append([]byte(nil), truncated...)
		if clampTCPMSS(truncated, 1200) || !bytes.Equal(truncated, before) {
			t.Fatal("truncated packet was modified")
		}
	}
	for _, mutate := range []func([]byte){
		func(p []byte) { p[9] = 17 },
		func(p []byte) { p[6] = 0x20 },
		func(p []byte) { p[offset+13] = 0x10 },
		func(p []byte) { p[offset+13] = 3 },
		func(p []byte) { p[offset+12] = 0xf0 },
		func(p []byte) { p[offset+21] = 3 },
	} {
		input := append([]byte(nil), packet...)
		mutate(input)
		before := append([]byte(nil), input...)
		if clampTCPMSS(input, 1200) || !bytes.Equal(input, before) {
			t.Fatal("non-SYN, malformed or fragmented traffic was modified")
		}
	}
	for _, next := range []byte{44, 50, 51} {
		input, _ := mssPacket(true, true, []byte{2, 4, 5, 180})
		input[6] = next
		before := append([]byte(nil), input...)
		if clampTCPMSS(input, 1200) || !bytes.Equal(input, before) {
			t.Fatal("fragment or IPsec traffic was modified")
		}
	}
}
