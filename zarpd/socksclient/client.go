// Package socksclient talks only to an authenticated private backend ingress.
package socksclient

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

var errProtocol = errors.New("private SOCKS transport failed")

type Client struct {
	Address            netip.AddrPort
	Username, Password string
}

func (Client) String() string   { return "PrivateSOCKSClient(redacted)" }
func (Client) GoString() string { return "PrivateSOCKSClient(redacted)" }

func (c Client) DialContext(parent context.Context, network, address string) (net.Conn, error) {
	if c.Address.Addr() != netip.MustParseAddr("127.0.0.1") || c.Address.Port() == 0 || c.Username == "" || len(c.Username) > 255 || c.Password == "" || len(c.Password) > 255 {
		return nil, errProtocol
	}
	if network != "tcp" && network != "tcp4" && network != "tcp6" && network != "udp" {
		return nil, errProtocol
	}
	destination, err := destinationBytes(address)
	if err != nil {
		return nil, errProtocol
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	control, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp4", c.Address.String())
	if err != nil {
		return nil, errProtocol
	}
	stop := context.AfterFunc(ctx, func() { control.Close() })
	defer stop()
	transferred := false
	defer func() {
		if !transferred {
			control.Close()
		}
	}()
	_ = control.SetDeadline(time.Now().Add(15 * time.Second))
	if writeAll(control, []byte{5, 1, 2}) != nil {
		return nil, errProtocol
	}
	var reply [2]byte
	if _, err = io.ReadFull(control, reply[:]); err != nil || reply != [2]byte{5, 2} {
		return nil, errProtocol
	}
	auth := append([]byte{1, byte(len(c.Username))}, c.Username...)
	auth = append(auth, byte(len(c.Password)))
	auth = append(auth, c.Password...)
	if writeAll(control, auth) != nil {
		return nil, errProtocol
	}
	if _, err = io.ReadFull(control, reply[:]); err != nil || reply != [2]byte{1, 0} {
		return nil, errProtocol
	}
	command := byte(1)
	var datagrams *net.UDPConn
	if network == "udp" {
		if _, err := netip.ParseAddrPort(address); err != nil {
			return nil, errProtocol
		}
		datagrams, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return nil, errProtocol
		}
		defer func() {
			if !transferred {
				datagrams.Close()
			}
		}()
		command = 3
		destination = []byte{1, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint16(destination[5:], uint16(datagrams.LocalAddr().(*net.UDPAddr).Port))
	}
	if writeAll(control, append([]byte{5, command, 0}, destination...)) != nil {
		return nil, errProtocol
	}
	var header [3]byte
	if _, err = io.ReadFull(control, header[:]); err != nil || header != [3]byte{5, 0, 0} {
		return nil, errProtocol
	}
	bound, err := readDestination(control)
	if err != nil || ctx.Err() != nil {
		return nil, errProtocol
	}
	_ = control.SetDeadline(time.Time{})
	if network != "udp" {
		transferred = true
		return control, nil
	}
	peer, err := netip.ParseAddrPort(bound)
	if err != nil || peer.Port() == 0 {
		return nil, errProtocol
	}
	if peer.Addr().IsUnspecified() {
		peer = netip.AddrPortFrom(c.Address.Addr(), peer.Port())
	}
	if peer.Addr() != c.Address.Addr() {
		return nil, errProtocol
	}
	remote, _ := netip.ParseAddrPort(address)
	packet := &packetConn{UDPConn: datagrams, control: control, peer: peer, remote: remote}
	transferred = true
	go func() { _, _ = io.Copy(io.Discard, control); packet.Close() }()
	return packet, nil
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func destinationBytes(address string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(address)
	port, parseErr := strconv.ParseUint(portText, 10, 16)
	if err != nil || parseErr != nil || port == 0 {
		return nil, errProtocol
	}
	var result []byte
	if ip, err := netip.ParseAddr(host); err == nil && ip.Zone() == "" {
		if ip.Is4() {
			result = append([]byte{1}, ip.AsSlice()...)
		} else {
			result = append([]byte{4}, ip.AsSlice()...)
		}
	} else {
		if len(host) == 0 || len(host) > 253 {
			return nil, errProtocol
		}
		for _, b := range []byte(host) {
			if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '.' || b == '-') {
				return nil, errProtocol
			}
		}
		result = append([]byte{3, byte(len(host))}, host...)
	}
	return append(result, byte(port>>8), byte(port)), nil
}

func readDestination(reader io.Reader) (string, error) {
	var kind [1]byte
	if _, err := io.ReadFull(reader, kind[:]); err != nil {
		return "", errProtocol
	}
	addressKind := kind[0]
	n := 0
	switch kind[0] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		if _, err := io.ReadFull(reader, kind[:]); err != nil {
			return "", errProtocol
		}
		n = int(kind[0])
	default:
		return "", errProtocol
	}
	if n == 0 {
		return "", errProtocol
	}
	data := make([]byte, n+2)
	if _, err := io.ReadFull(reader, data); err != nil {
		return "", errProtocol
	}
	host := string(data[:n])
	if addressKind == 1 || addressKind == 4 {
		if ip, ok := netip.AddrFromSlice(data[:n]); ok {
			host = ip.String()
		}
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(data[n:])))), nil
}

type packetConn struct {
	*net.UDPConn
	control      net.Conn
	peer, remote netip.AddrPort
	once         sync.Once
}

func (c *packetConn) Write(data []byte) (int, error) {
	header, err := destinationBytes(c.remote.String())
	if err != nil {
		return 0, err
	}
	packet := append([]byte{0, 0, 0}, header...)
	packet = append(packet, data...)
	if len(packet) > 65507 {
		return 0, errProtocol
	}
	n, err := c.UDPConn.WriteToUDPAddrPort(packet, c.peer)
	if err != nil || n != len(packet) {
		if err == nil {
			err = io.ErrShortWrite
		}
		return 0, err
	}
	return len(data), nil
}
func (c *packetConn) Read(data []byte) (int, error) {
	buffer := make([]byte, 65535)
	for {
		n, peer, err := c.UDPConn.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return 0, err
		}
		if peer != c.peer || n < 4 || buffer[0] != 0 || buffer[1] != 0 || buffer[2] != 0 {
			continue
		}
		header, err := destinationBytes(c.remote.String())
		if err != nil {
			return 0, err
		}
		if n < 3+len(header) {
			continue
		}
		matches := true
		for i := range header {
			if buffer[3+i] != header[i] {
				matches = false
				break
			}
		}
		if !matches {
			continue
		}
		payload := buffer[3+len(header) : n]
		if len(payload) > len(data) {
			return 0, io.ErrShortBuffer
		}
		return copy(data, payload), nil
	}
}
func (c *packetConn) Close() error {
	var err error
	c.once.Do(func() { c.control.Close(); err = c.UDPConn.Close() })
	return err
}
func (c *packetConn) RemoteAddr() net.Addr { return net.UDPAddrFromAddrPort(c.remote) }
