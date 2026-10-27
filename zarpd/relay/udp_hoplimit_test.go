package relay

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/feg55/zarp-macos/zarpd/internal/socketopts"
)

func TestFakeHopLimitFailureRestoresAndStopsBeforeRealTraffic(t *testing.T) {
	failure := errors.New("private injected failure")
	restore := errors.New("private injected restore failure")
	for _, mode := range []string{"ok", "default", "inherited", "invalid", "get", "unknown", "set", "write", "short", "restore", "write-restore"} {
		t.Run(mode, func(t *testing.T) {
			var events []string
			var values []int
			limit := 1
			if mode == "default" {
				limit = 0
			}
			if mode == "invalid" {
				limit = 256
			}
			get := func() (int, error) {
				events = append(events, "get")
				if mode == "get" {
					return 0, failure
				}
				if mode == "unknown" {
					return 0, nil
				}
				if mode == "inherited" {
					return -1, nil
				}
				return 64, nil
			}
			set := func(n int) error {
				events = append(events, "set")
				values = append(values, n)
				if mode == "set" && n == 1 {
					return failure
				}
				if (mode == "restore" || mode == "write-restore") && n == 64 {
					return restore
				}
				return nil
			}
			write := func(p []byte) (int, error) {
				events = append(events, "write")
				if mode == "write" || mode == "write-restore" {
					return 0, failure
				}
				if mode == "short" {
					return 0, nil
				}
				return len(p), nil
			}
			err := sendFakeWithHopLimit([]byte("fake"), limit, mode == "inherited", get, set, write)
			expected := []string{"get", "set", "write", "set"}
			switch mode {
			case "default":
				expected = []string{"write"}
			case "invalid":
				expected = nil
			case "get", "unknown":
				expected = []string{"get"}
			case "set":
				expected = []string{"get", "set", "set"}
			}
			if !reflect.DeepEqual(events, expected) {
				t.Fatal("unsafe fake send/restore order", events)
			}
			normal := 64
			if mode == "inherited" {
				normal = -1
			}
			if len(values) > 0 && !reflect.DeepEqual(values, []int{1, normal}) {
				t.Fatal("original socket limit was not restored", values)
			}
			if (mode == "ok" || mode == "default" || mode == "inherited") != (err == nil) {
				t.Fatal("failed fake/restore reported success")
			}
			if mode == "short" && !errors.Is(err, io.ErrShortWrite) {
				t.Fatal("short write lost")
			}
			if mode == "write-restore" && (!errors.Is(err, failure) || !errors.Is(err, restore)) {
				t.Fatal("restore failure hidden behind write failure")
			}
		})
	}
}

func TestPrivateConnectedUDPFakeRestoresOriginalSocketHopLimit(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			ip := net.IPv4(127, 0, 0, 1)
			ipv6 := network == "udp6"
			if ipv6 {
				ip = net.IPv6loopback
			}
			server, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			client, err := net.DialUDP(network, nil, server.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			inherited, err := socketopts.HopLimit(client, ipv6)
			if err != nil {
				t.Fatal(err)
			}
			if err := sendFakeDatagram(client, ipv6, []byte("inherited-fake"), 1); err != nil {
				t.Fatal(err)
			}
			if value, err := socketopts.HopLimit(client, ipv6); err != nil || value != inherited {
				t.Fatal("inherited private socket policy changed", value, err)
			}
			if err := socketopts.SetHopLimit(client, ipv6, 73); err != nil {
				t.Fatal(err)
			}
			if err := sendFakeDatagram(client, ipv6, []byte("fake"), 1); err != nil {
				t.Fatal(err)
			}
			if value, err := socketopts.HopLimit(client, ipv6); err != nil || value != 73 {
				t.Fatal("explicit private socket limit changed", value, err)
			}
			if _, err := client.Write([]byte("real")); err != nil {
				t.Fatal(err)
			}
			server.SetReadDeadline(time.Now().Add(time.Second))
			var peer string
			for _, payload := range []string{"inherited-fake", "fake", "real"} {
				buffer := make([]byte, 32)
				n, source, err := server.ReadFromUDPAddrPort(buffer)
				if err != nil || string(buffer[:n]) != payload {
					t.Fatal("fake/real private datagrams missing")
				}
				if peer != "" && peer != source.String() {
					t.Fatal("outer tuple changed")
				}
				peer = source.String()
			}
		})
	}
}

func TestUDPFakeHopLimitBoundsRefuseBeforeListener(t *testing.T) {
	for _, limit := range []int{-1, 256} {
		r, err := StartUDP(context.Background(), UDPConfig{Target: netip.MustParseAddrPort("127.0.0.1:443"), Username: "fixture", Password: "private", Lifetime: time.Second, Fake: []byte("fake"), FakeHopLimit: limit})
		if r != nil || err == nil {
			if r != nil {
				r.Close()
			}
			t.Fatal("invalid fake hop limit created a listener")
		}
	}
}
