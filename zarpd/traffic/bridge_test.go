package traffic

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/feg55/zarp-macos/zarpd/connection"
	"github.com/feg55/zarp-macos/zarpd/tunproxy"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type labelledBackend struct{ tcp, udp, label string }

func (d labelledBackend) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	address := d.tcp
	if network == "udp" {
		address = d.udp
	}
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func echoBackend(t *testing.T, label string) labelledBackend {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close(); udp.Close() })
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				payload := make([]byte, 7)
				if _, err := io.ReadFull(c, payload); err == nil {
					_, _ = c.Write(append([]byte(label+":"), payload...))
				}
			}(c)
		}
	}()
	go func() {
		payload := make([]byte, 65535)
		for {
			n, peer, err := udp.ReadFromUDP(payload)
			if err != nil {
				return
			}
			_, _ = udp.WriteToUDP(append([]byte(label+":"), payload[:n]...), peer)
		}
	}()
	return labelledBackend{tcp: listener.Addr().String(), udp: udp.LocalAddr().String(), label: label}
}

type sourceOwner struct {
	source     netip.Addr
	executable string
}

func (o sourceOwner) Owner(_ context.Context, flow tunproxy.Flow) (Owner, error) {
	if flow.Source.Addr() != o.source || flow.Source.Port() == 0 {
		return Owner{}, errors.New("original source metadata lost")
	}
	return Owner{PID: 77, Executable: o.executable}, nil
}

func TestOriginalIPFlowsCarrySelectedAndExcludedTCPUDPToDifferentBackends(t *testing.T) {
	proxy, direct := echoBackend(t, "server"), echoBackend(t, "direct")
	for _, family := range []struct{ source, destination string }{{"10.88.0.2", "198.18.1.1"}, {"fd00:88::2", "2001:db8::1"}} {
		for _, selected := range []bool{true, false} {
			label := "excluded"
			path := "/Applications/Other.app/Contents/MacOS/Other"
			if selected {
				label = "selected"
				path = "/Applications/Browser.app/Contents/Frameworks/Helper.app/Contents/MacOS/Helper"
			}
			t.Run(family.source+"/"+label, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				policy := connection.DefaultRoutingPolicy()
				policy.ApplicationMode = "include"
				policy.ApplicationPaths = []string{"/Applications/Browser.app"}
				router, err := New(Config{Policy: policy, Proxy: proxy, Direct: direct, Owners: sourceOwner{source: netip.MustParseAddr(family.source), executable: path}})
				if err != nil {
					t.Fatal(err)
				}
				bridge, err := tunproxy.New(ctx, router, 1280)
				if err != nil {
					t.Fatal(err)
				}
				device, peer, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(family.source)}, nil, 1280)
				if err != nil {
					bridge.Stop()
					t.Fatal(err)
				}
				var pumps sync.WaitGroup
				pumps.Add(2)
				go func() {
					defer pumps.Done()
					buffers := [][]byte{make([]byte, 2000)}
					sizes := make([]int, 1)
					for {
						n, err := device.Read(buffers, sizes, 0)
						if err != nil {
							return
						}
						if n == 1 {
							_ = bridge.Inject(append([]byte(nil), buffers[0][:sizes[0]]...))
						}
					}
				}()
				go func() {
					defer pumps.Done()
					for {
						packet, err := bridge.ReadPacket(ctx)
						if err != nil {
							return
						}
						if _, err := device.Write([][]byte{packet}, 0); err != nil {
							return
						}
					}
				}()
				defer func() { cancel(); bridge.Stop(); device.Close(); pumps.Wait(); bridge.Wait() }()
				destination := netip.MustParseAddr(family.destination)
				for _, network := range []string{"tcp", "udp"} {
					var socket net.Conn
					if network == "tcp" {
						socket, err = peer.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(destination, 443))
					} else {
						socket, err = peer.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(destination, 9999))
					}
					if err != nil {
						t.Fatal(err)
					}
					_ = socket.SetDeadline(time.Now().Add(3 * time.Second))
					if _, err := socket.Write([]byte("payload")); err != nil {
						socket.Close()
						t.Fatal(err)
					}
					want := "direct:payload"
					if selected {
						want = "server:payload"
					}
					response := make([]byte, len(want))
					_, err := io.ReadFull(socket, response)
					socket.Close()
					if err != nil || string(response) != want {
						t.Fatal("wrong routed payload", network, err)
					}
				}
			})
		}
	}
}
