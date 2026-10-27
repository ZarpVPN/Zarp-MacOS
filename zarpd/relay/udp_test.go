package relay

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func associate(t *testing.T, address, user, password string) (net.Conn, *net.UDPConn) {
	t.Helper()
	control, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { control.Close() })
	_ = control.SetDeadline(time.Now().Add(3 * time.Second))
	if writeAll(control, []byte{5, 1, 2}) != nil {
		t.Fatal("greeting failed")
	}
	var response [2]byte
	if _, err := io.ReadFull(control, response[:]); err != nil || response != [2]byte{5, 2} {
		t.Fatal("authentication method rejected")
	}
	auth := append([]byte{1, byte(len(user))}, []byte(user)...)
	auth = append(auth, byte(len(password)))
	auth = append(auth, []byte(password)...)
	if writeAll(control, auth) != nil {
		t.Fatal("auth write failed")
	}
	if _, err := io.ReadFull(control, response[:]); err != nil || response != [2]byte{1, 0} {
		t.Fatal("auth rejected")
	}
	if writeAll(control, []byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}) != nil {
		t.Fatal("associate failed")
	}
	var reply [10]byte
	if _, err := io.ReadFull(control, reply[:]); err != nil || reply[1] != 0 {
		t.Fatal("associate reply failed")
	}
	destination, err := readAddress(bytes.NewReader(reply[4:]), reply[3])
	if err != nil {
		t.Fatal(err)
	}
	socket, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(destination))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { socket.Close() })
	_ = socket.SetDeadline(time.Now().Add(3 * time.Second))
	return control, socket
}

func TestUDPOrderingTupleAndCleanup(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			ip := net.ParseIP("127.0.0.1")
			if network == "udp6" {
				ip = net.ParseIP("::1")
			}
			server, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			target := server.LocalAddr().(*net.UDPAddr).AddrPort()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fake := []byte("invalid-loopback-fake")
			relay, err := StartUDP(ctx, UDPConfig{Target: target, Username: "test", Password: "private", Lifetime: 5 * time.Second, Fake: fake})
			if err != nil {
				t.Fatal(err)
			}
			defer relay.Close()
			control, socket := associate(t, relay.Address(), "test", "private")
			// A fragmented SOCKS datagram must not become an upstream fake or real packet.
			invalid := encodeUDP(target, []byte("invalid"))
			invalid[2] = 1
			socket.Write(invalid)
			socket.Write(encodeUDP(netip.AddrPortFrom(target.Addr(), 1), []byte("wrong-target")))
			socket.Write(encodeUDP(target, []byte("real-initial")))
			_ = server.SetReadDeadline(time.Now().Add(time.Second))
			buffer := make([]byte, 2048)
			n, first, err := server.ReadFromUDPAddrPort(buffer)
			if err != nil || !bytes.Equal(buffer[:n], fake) {
				t.Fatal("fake was not first")
			}
			n, second, err := server.ReadFromUDPAddrPort(buffer)
			if err != nil || string(buffer[:n]) != "real-initial" || first != second {
				t.Fatal("real packet did not follow fake on the same outer tuple")
			}
			server.WriteToUDPAddrPort([]byte("actual-response"), second)
			n, err = socket.Read(buffer)
			if err != nil {
				t.Fatal(err)
			}
			payload, ok := decodeUDP(buffer[:n], target)
			if !ok || string(payload) != "actual-response" {
				t.Fatal("lost reverse datagram")
			}
			socket.Write(encodeUDP(target, []byte("real-second")))
			n, third, err := server.ReadFromUDPAddrPort(buffer)
			if err != nil || string(buffer[:n]) != "real-second" || third != first {
				t.Fatal("repeated fake or changed tuple within association")
			}
			control.Close()
			cancel()
			done := make(chan struct{})
			go func() { relay.Close(); close(done) }()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("UDP cleanup leaked a blocked worker")
			}
		})
	}
}
