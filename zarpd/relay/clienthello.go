// Package relay implements a bounded transport relay PoC. It has no TUN, route or DNS code.
package relay

import (
	"encoding/binary"
	"errors"
	"io"
)

const maxHelloBytes = 65535

var errClientHello = errors.New("invalid outer TLS ClientHello")

// Hello preserves original TLS records and maps the SNI offset back to the wire stream.
// Fragmented reads and handshake messages spanning records must not change the technique.
type Hello struct {
	Wire        []byte
	ServerName  string
	HostOffset  int
	ALPN        []string
	hostOffsets []int
}

func ReadClientHello(reader io.Reader) (Hello, error) {
	return readClientHello(reader, false)
}

func readClientHello(reader io.Reader, allowNoSNI bool) (Hello, error) {
	var wire, handshake []byte
	var offsets []int
	wanted := 0
	for wanted == 0 || len(handshake) < wanted {
		var header [5]byte
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			return Hello{}, errClientHello
		}
		length := int(binary.BigEndian.Uint16(header[3:]))
		if header[0] != 22 || header[1] != 3 || length == 0 || length > 16384 || len(wire)+5+length > maxHelloBytes {
			return Hello{}, errClientHello
		}
		start := len(wire) + 5
		body := make([]byte, length)
		if _, err := io.ReadFull(reader, body); err != nil {
			return Hello{}, errClientHello
		}
		wire = append(wire, header[:]...)
		wire = append(wire, body...)
		for index := range body {
			offsets = append(offsets, start+index)
		}
		handshake = append(handshake, body...)
		if len(handshake) >= 4 && wanted == 0 {
			wanted = 4 + (int(handshake[1]) << 16) + (int(handshake[2]) << 8) + int(handshake[3])
			if handshake[0] != 1 || wanted < 42 || wanted > maxHelloBytes {
				return Hello{}, errClientHello
			}
		}
	}
	data := handshake[:wanted]
	at := 4 + 2 + 32
	readVector := func(width int) ([]byte, bool) {
		if at+width > len(data) {
			return nil, false
		}
		n := int(data[at])
		if width == 2 {
			n = int(binary.BigEndian.Uint16(data[at:]))
		}
		at += width
		if at+n > len(data) {
			return nil, false
		}
		value := data[at : at+n]
		at += n
		return value, true
	}
	if _, ok := readVector(1); !ok {
		return Hello{}, errClientHello
	}
	if suites, ok := readVector(2); !ok || len(suites) == 0 || len(suites)%2 != 0 {
		return Hello{}, errClientHello
	}
	if compression, ok := readVector(1); !ok || len(compression) == 0 {
		return Hello{}, errClientHello
	}
	extensions, ok := readVector(2)
	if !ok || at != wanted {
		return Hello{}, errClientHello
	}
	extStart := at - len(extensions)
	hello := Hello{Wire: wire, HostOffset: -1}
	seen := map[uint16]bool{}
	for index := 0; index < len(extensions); {
		if index+4 > len(extensions) {
			return Hello{}, errClientHello
		}
		kind := binary.BigEndian.Uint16(extensions[index:])
		length := int(binary.BigEndian.Uint16(extensions[index+2:]))
		index += 4
		if index+length > len(extensions) || seen[kind] {
			return Hello{}, errClientHello
		}
		seen[kind] = true
		value := extensions[index : index+length]
		switch kind {
		case 0:
			if len(value) < 5 || int(binary.BigEndian.Uint16(value)) != len(value)-2 || value[2] != 0 {
				return Hello{}, errClientHello
			}
			n := int(binary.BigEndian.Uint16(value[3:]))
			if n == 0 || n > 253 || n+5 != len(value) {
				return Hello{}, errClientHello
			}
			hello.ServerName = string(value[5:])
			hello.HostOffset = offsets[extStart+index+5]
			hello.hostOffsets = append([]int(nil), offsets[extStart+index+5:extStart+index+5+n]...)
		case 16:
			if len(value) < 3 || int(binary.BigEndian.Uint16(value)) != len(value)-2 {
				return Hello{}, errClientHello
			}
			for offset := 2; offset < len(value); {
				n := int(value[offset])
				offset++
				if n == 0 || offset+n > len(value) || len(hello.ALPN) >= 8 {
					return Hello{}, errClientHello
				}
				hello.ALPN = append(hello.ALPN, string(value[offset:offset+n]))
				offset += n
			}
		}
		index += length
	}
	if hello.HostOffset < 0 && !allowNoSNI {
		return Hello{}, errClientHello
	}
	return hello, nil
}
