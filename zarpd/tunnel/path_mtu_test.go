package tunnel

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	usqueconfig "github.com/Diniboy1123/usque/config"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/feg55/zarp-macos/zarpd/warp"
)

// These devices exist only in userspace. No OS TUN, route or DNS is created.
type closeOnceMemoryDevice struct {
	tun.Device
	once     sync.Once
	stop     chan struct{}
	packets  chan []byte
	readDone chan struct{}
}

func queuedMemoryDevice(raw tun.Device) *closeOnceMemoryDevice {
	d := &closeOnceMemoryDevice{Device: raw, stop: make(chan struct{}), packets: make(chan []byte, 128), readDone: make(chan struct{})}
	// Drain synchronous netstack notifications independently of ICMP ingress.
	// A sender holding its TCP lock must not block the packet reader needed to
	// inject its Packet Too Big response.
	go func() {
		defer close(d.readDone)
		defer close(d.packets)
		buf := make([]byte, 2048)
		sizes := make([]int, 1)
		for {
			n, err := raw.Read([][]byte{buf}, sizes, 0)
			if err != nil {
				return
			}
			if n > 0 {
				pkt := append([]byte(nil), buf[:sizes[0]]...)
				select {
				case d.packets <- pkt:
				case <-d.stop:
				}
			}
		}
	}()
	return d
}

func (d *closeOnceMemoryDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	packet, ok := <-d.packets
	if !ok {
		return 0, os.ErrClosed
	}
	if len(packet) > len(bufs[0])-offset {
		return 0, io.ErrShortBuffer
	}
	sizes[0] = copy(bufs[0][offset:], packet)
	return 1, nil
}

func (d *closeOnceMemoryDevice) Close() error {
	d.once.Do(func() { close(d.stop); _ = d.Device.Close(); <-d.readDone })
	return nil
}

func privatePathTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientDER, _ := x509.MarshalECPrivateKey(clientKey)
	publicDER, _ := x509.MarshalPKIXPublicKey(&serverKey.PublicKey)
	certDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}, &x509.Certificate{}, &serverKey.PublicKey, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	client, err := warp.TLSConfigFromAccount(&usqueconfig.Config{PrivateKey: base64.StdEncoding.EncodeToString(clientDER), EndpointPubKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}))})
	if err != nil {
		t.Fatal(err)
	}
	server := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{certDER}, PrivateKey: serverKey}}, ClientAuth: tls.RequireAnyClientCert}
	return client, server
}

// A fixed UDP ceiling models a path where larger PMTU probes are lost. All
// physical sockets bind numeric loopback and forward only to one private peer.
func privateLimitedUDPPath(t *testing.T, target *net.UDPAddr, ceiling int) *net.UDPAddr {
	t.Helper()
	front, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	back, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		front.Close()
		t.Fatal(err)
	}
	var mu sync.Mutex
	var client *net.UDPAddr
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		buf := make([]byte, 65536)
		for {
			n, addr, err := front.ReadFromUDP(buf)
			if err != nil {
				return
			}
			mu.Lock()
			client = addr
			mu.Unlock()
			if n <= ceiling {
				_, _ = back.WriteToUDP(buf[:n], target)
			}
		}
	}()
	go func() {
		defer workers.Done()
		buf := make([]byte, 65536)
		for {
			n, addr, err := back.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if !addr.IP.Equal(target.IP) || addr.Port != target.Port {
				continue
			}
			mu.Lock()
			peer := client
			mu.Unlock()
			if peer != nil && n <= ceiling {
				_, _ = front.WriteToUDP(buf[:n], peer)
			}
		}
	}()
	t.Cleanup(func() { front.Close(); back.Close(); workers.Wait() })
	return front.LocalAddr().(*net.UDPAddr)
}

func TestH3PumpCarriesHTTPSOnA1280ByteUDPPath(t *testing.T) {
	for _, family := range []int{4, 6} {
		t.Run(fmt.Sprint(family), func(t *testing.T) {
			clientIP, serverIP := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("198.51.100.20")
			if family == 6 {
				clientIP = netip.MustParseAddr("2001:db8:1::10")
				serverIP = netip.MustParseAddr("2001:db8:2::20")
			}
			clientDevice, clientNetwork, err := netstack.CreateNetTUN([]netip.Addr{clientIP}, nil, 1280)
			if err != nil {
				t.Fatal(err)
			}
			clientDev := queuedMemoryDevice(clientDevice)
			defer clientDev.Close()
			serverDevice, serverNetwork, err := netstack.CreateNetTUN([]netip.Addr{serverIP}, nil, 1280)
			if err != nil {
				t.Fatal(err)
			}
			serverDev := queuedMemoryDevice(serverDevice)
			defer serverDev.Close()
			listener, err := serverNetwork.ListenTCPAddrPort(netip.AddrPortFrom(serverIP, 443))
			if err != nil {
				t.Fatal(err)
			}
			innerClientTLS, innerServerTLS := privatePathTLS(t)
			innerClientTLS.NextProtos = []string{"http/1.1"}
			innerServerTLS.NextProtos = []string{"http/1.1"}
			https := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.Copy(w, io.LimitReader(r.Body, 65536)) })}
			httpsDone := make(chan struct{})
			go func() { defer close(httpsDone); _ = https.Serve(tls.NewListener(listener, innerServerTLS)) }()
			defer func() { https.Close(); <-httpsDone }()
			clientTLS, serverTLS := privatePathTLS(t)
			udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			fixture := &http3.Server{TLSConfig: serverTLS, EnableDatagrams: true,
				QUICConfig: &quic.Config{InitialPacketSize: 1280, DisablePathMTUDiscovery: true},
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set(http3.CapsuleProtocolHeader, "?1")
					w.WriteHeader(http.StatusOK)
					stream := w.(http3.HTTPStreamer).HTTPStream()
					stop := context.AfterFunc(r.Context(), func() { serverDev.Close() })
					defer stop()
					readDone := make(chan struct{})
					go func() {
						defer close(readDone)
						buffer := make([]byte, 2048)
						sizes := make([]int, 1)
						for {
							n, err := serverDev.Read([][]byte{buffer}, sizes, 0)
							if err != nil {
								return
							}
							if n > 0 {
								data := append([]byte{0}, buffer[:sizes[0]]...)
								if err := stream.SendDatagram(data); err != nil {
									return
								}
							}
						}
					}()
					defer func() { serverDev.Close(); <-readDone }()
					for {
						data, err := stream.ReceiveDatagram(r.Context())
						if err != nil {
							return
						}
						if len(data) > 1 && data[0] == 0 {
							if _, err = serverDev.Write([][]byte{data[1:]}, 0); err != nil {
								return
							}
						}
					}
				})}
			served := make(chan struct{})
			go func() { defer close(served); _ = fixture.Serve(udp) }()
			defer func() { fixture.Close(); <-served }()
			endpoint := privateLimitedUDPPath(t, udp.LocalAddr().(*net.UDPAddr), 1280)
			local, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			session, err := warp.DialH3WithStrategy(context.Background(), local, endpoint, clientTLS, time.Second, 3*time.Second,
				[]warp.FakeStep{{Blob: []byte("private-path-decoy"), Repeats: 2}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			pump := New(clientDev, session, 1280)
			pumped := make(chan struct{})
			go func() { defer close(pumped); _ = pump.Run() }()
			defer func() { session.Close(); clientDev.Close(); <-pumped }()
			transport := &http.Transport{TLSClientConfig: innerClientTLS, DialContext: clientNetwork.DialContext, DisableKeepAlives: true}
			defer transport.CloseIdleConnections()
			payload := bytes.Repeat([]byte("private-path-https"), 1024)
			address := "https://" + net.JoinHostPort(serverIP.String(), "443") + "/"
			response, err := (&http.Client{Transport: transport, Timeout: 4 * time.Second}).Post(address, "application/octet-stream", bytes.NewReader(payload))
			if err != nil {
				t.Fatal("HTTPS over the limited UDP path:", err)
			}
			defer response.Body.Close()
			got, err := io.ReadAll(io.LimitReader(response.Body, int64(len(payload)+1)))
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatal("HTTPS payload failed", err)
			}
			stats, ok := session.QUICStatistics()
			if !ok || stats.MSSOut == 0 || stats.MSSIn == 0 || stats.PacketTooBig != 0 || stats.SampledTX == 0 || stats.SampledRX == 0 {
				t.Fatalf("missing bidirectional MSS or unexpected packet overflow: %+v", stats)
			}
		})
	}
}
