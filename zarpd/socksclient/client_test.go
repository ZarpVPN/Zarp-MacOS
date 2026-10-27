package socksclient_test

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/feg55/zarp-macos/zarpd/relay"
	"github.com/feg55/zarp-macos/zarpd/socksclient"
)

func TestAuthenticatedPrivateSOCKSTransfersTCPAndUDP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		c, err := tcp.Accept()
		if err == nil {
			defer c.Close()
			_, _ = io.Copy(c, c)
		}
	}()
	go func() {
		buf := make([]byte, 1000)
		for {
			n, peer, err := udp.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = udp.WriteToUDP(buf[:n], peer)
		}
	}()
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			target := netip.MustParseAddrPort(tcp.Addr().String())
			if network == "udp" {
				target = udp.LocalAddr().(*net.UDPAddr).AddrPort()
			}
			r, err := relay.StartOuter(ctx, relay.OuterConfig{Target: target, Username: "private-user", Password: "private-password", UDP: network == "udp", AllowPlain: true})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				cleanup, stop := context.WithTimeout(context.Background(), time.Second)
				defer stop()
				if err := r.CloseBounded(cleanup); err != nil {
					t.Error(err)
				}
			}()
			client := socksclient.Client{Address: r.Address(), Username: "private-user", Password: "private-password"}
			conn, err := client.DialContext(ctx, network, target.String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			marker := []byte("authenticated-private-payload")
			if _, err = conn.Write(marker); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, len(marker))
			if _, err = io.ReadFull(conn, buf); err != nil || string(buf) != string(marker) {
				t.Fatal("private SOCKS payload mismatch", err)
			}
			wrong := client
			wrong.Password = "wrong"
			if c, err := wrong.DialContext(ctx, network, target.String()); err == nil {
				c.Close()
				t.Fatal("wrong private ingress credential accepted")
			}
		})
	}
}
