package tunproxy

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

type fixtureDialer struct{ tcp, udp string }

func (d fixtureDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	target := d.tcp
	if network == "udp" {
		target = d.udp
	}
	return (&net.Dialer{}).DialContext(ctx, network, target)
}

func TestUserspaceBridgeTransfersTCPUDPAndDNSOverBothIPFamilies(t *testing.T) {
	tcpListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	udpListener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpListener.Close()
	go func() {
		for {
			c, err := tcpListener.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, peer, err := udpListener.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			_, _ = udpListener.WriteToUDP(buffer[:n], peer)
		}
	}()
	for _, family := range []struct{ local, remote string }{{"10.88.0.2", "198.18.1.1"}, {"fd00:88::2", "2001:db8::1"}} {
		t.Run(family.local, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			bridge, err := New(ctx, fixtureDialer{tcpListener.Addr().String(), udpListener.LocalAddr().String()}, 1280)
			if err != nil {
				t.Fatal(err)
			}
			device, client, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(family.local)}, nil, 1280)
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
					if _, err = device.Write([][]byte{packet}, 0); err != nil {
						return
					}
				}
			}()
			defer func() { cancel(); bridge.Stop(); device.Close(); pumps.Wait(); bridge.Wait() }()
			remote := netip.MustParseAddr(family.remote)
			tcpConn, err := client.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(remote, 443))
			if err != nil {
				t.Fatal("in-memory TCP dial", err)
			}
			_ = tcpConn.SetDeadline(time.Now().Add(2 * time.Second))
			marker := []byte("private-tcp-payload")
			if _, err = tcpConn.Write(marker); err != nil {
				t.Fatal(err)
			}
			response := make([]byte, len(marker))
			if _, err = io.ReadFull(tcpConn, response); err != nil || string(response) != string(marker) {
				t.Fatal("TCP payload did not traverse the userspace bridge", err)
			}
			tcpConn.Close()
			for _, port := range []uint16{53, 9999} {
				udpConn, err := client.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(remote, port))
				if err != nil {
					t.Fatal(err)
				}
				_ = udpConn.SetDeadline(time.Now().Add(2 * time.Second))
				marker := []byte{0x12, 0x34, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0}
				if _, err = udpConn.Write(marker); err != nil {
					t.Fatal(err)
				}
				response := make([]byte, 100)
				n, err := udpConn.Read(response)
				if err != nil || string(response[:n]) != string(marker) {
					t.Fatal("UDP/DNS payload did not traverse the userspace bridge", err)
				}
				udpConn.Close()
			}
		})
	}
}
