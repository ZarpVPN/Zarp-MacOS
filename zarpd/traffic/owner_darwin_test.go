//go:build darwin && cgo

package traffic

import (
	"context"
	"github.com/feg55/zarp-macos/zarpd/tunproxy"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestNativeOwnerFindsOnlyTheOwnedTCPAndUDPLoopbackSockets(t *testing.T) {
	resolver := &NativeOwners{}
	for _, family := range []string{"4", "6"} {
		address := "127.0.0.1:0"
		if family == "6" {
			address = "[::1]:0"
		}
		for _, network := range []string{"tcp", "udp"} {
			t.Run(network+family, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				var socket net.Conn
				if network == "tcp" {
					listener, err := net.Listen("tcp"+family, address)
					if err != nil {
						t.Fatal(err)
					}
					defer listener.Close()
					go func() {
						c, err := listener.Accept()
						if err == nil {
							defer c.Close()
							<-ctx.Done()
						}
					}()
					socket, err = (&net.Dialer{}).DialContext(ctx, "tcp"+family, listener.Addr().String())
					if err != nil {
						t.Fatal(err)
					}
				} else {
					local, err := net.ResolveUDPAddr("udp"+family, address)
					if err != nil {
						t.Fatal(err)
					}
					listener, err := net.ListenUDP("udp"+family, local)
					if err != nil {
						t.Fatal(err)
					}
					defer listener.Close()
					socket, err = (&net.Dialer{}).DialContext(ctx, "udp"+family, listener.LocalAddr().String())
					if err != nil {
						t.Fatal(err)
					}
				}
				defer socket.Close()
				flow := tunproxy.Flow{Network: network}
				if network == "tcp" {
					flow.Source = socket.LocalAddr().(*net.TCPAddr).AddrPort()
					flow.Destination = socket.RemoteAddr().(*net.TCPAddr).AddrPort()
				} else {
					flow.Source = socket.LocalAddr().(*net.UDPAddr).AddrPort()
					flow.Destination = socket.RemoteAddr().(*net.UDPAddr).AddrPort()
				}
				owner, err := resolver.Owner(ctx, flow)
				if err != nil || owner.PID != os.Getpid() {
					t.Fatal("own socket identity not resolved", err)
				}
				ownBinary, _ := os.Executable()
				a, _ := os.Stat(ownBinary)
				b, err := os.Stat(owner.Executable)
				if err != nil || !os.SameFile(a, b) {
					t.Fatal("own executable identity differs")
				}
			})
		}
	}
}

func TestNativeOwnerFindsUnconnectedWildcardUDPSocket(t *testing.T) {
	resolver := &NativeOwners{}
	for _, family := range []string{"4", "6"} {
		t.Run(family, func(t *testing.T) {
			local, destination := "0.0.0.0:0", "127.0.0.1:0"
			if family == "6" {
				local, destination = "[::]:0", "[::1]:0"
			}
			endpoint, err := net.ResolveUDPAddr("udp"+family, destination)
			if err != nil {
				t.Fatal(err)
			}
			listener, err := net.ListenUDP("udp"+family, endpoint)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			address, err := net.ResolveUDPAddr("udp"+family, local)
			if err != nil {
				t.Fatal(err)
			}
			socket, err := net.ListenUDP("udp"+family, address)
			if err != nil {
				t.Fatal(err)
			}
			defer socket.Close()
			if _, err := socket.WriteToUDP([]byte("owned-loopback"), listener.LocalAddr().(*net.UDPAddr)); err != nil {
				t.Fatal(err)
			}
			port := socket.LocalAddr().(*net.UDPAddr).AddrPort().Port()
			peer := listener.LocalAddr().(*net.UDPAddr).AddrPort()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			owner, err := resolver.Owner(ctx, tunproxy.Flow{Network: "udp", Source: netip.AddrPortFrom(peer.Addr(), port), Destination: peer})
			if err != nil || owner.PID != os.Getpid() {
				t.Fatal("wildcard UDP owner not resolved", err)
			}
		})
	}
}
