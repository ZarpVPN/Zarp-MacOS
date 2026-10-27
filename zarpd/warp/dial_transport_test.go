package warp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	usqueconfig "github.com/Diniboy1123/usque/config"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// These fixtures exercise the product dialers with real pinned TLS and IP
// payloads, using numeric loopback only. They never create an OS tunnel.
func masqueLoopbackTLS(t *testing.T) (client, server *tls.Config) {
	return masqueLoopbackTLSForName(t, "")
}

func masqueLoopbackTLSForName(t *testing.T, name string) (client, server *tls.Config) {
	t.Helper()
	_, clientDER, _, err := generateECKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	key, _, publicDER, err := generateECKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := generateSelfSignedCert(key)
	if err != nil {
		t.Fatal(err)
	}
	client, err = TLSConfigForStrategy(&usqueconfig.Config{
		PrivateKey:     base64.StdEncoding.EncodeToString(clientDER),
		EndpointPubKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})),
	}, name)
	if err != nil {
		t.Fatal(err)
	}
	expectedName := client.ServerName
	server = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: certificate, PrivateKey: key}},
		ClientAuth:   tls.RequireAnyClientCert,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if hello.ServerName != expectedName {
				return nil, fmt.Errorf("unexpected outer TLS name: %q", hello.ServerName)
			}
			return nil, nil
		},
	}
	return client, server
}

func masqueLoopbackPacket(sequence byte) []byte {
	packet := make([]byte, 32)
	packet[0], packet[8], packet[9] = 0x45, 64, 253
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], net.ParseIP("192.0.2.10").To4())
	copy(packet[16:20], net.ParseIP("198.51.100.20").To4())
	copy(packet[20:], []byte("zarp-payload"))
	packet[len(packet)-1] = sequence
	return packet
}

func exchangeMasqueLoopbackPacket(t *testing.T, session *Session, sequence byte) {
	t.Helper()
	result := make(chan error, 1)
	go func() {
		packet := masqueLoopbackPacket(sequence)
		if icmp, err := session.IPConn.WritePacket(packet); err != nil || len(icmp) != 0 {
			result <- fmt.Errorf("write packet: %v (ICMP bytes: %d)", err, len(icmp))
			return
		}
		echo, err := session.IPConn.ReadPacketZeroCopy(true)
		if err != nil {
			result <- err
			return
		}
		if !bytes.Equal(echo, packet) {
			result <- fmt.Errorf("echo payload differs (got %d bytes, want %d)", len(echo), len(packet))
			return
		}
		result <- nil
	}()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		session.Close()
		select {
		case <-result:
		case <-time.After(time.Second):
			t.Error("packet exchange did not stop after session close")
		}
		t.Fatal("loopback IP packet exchange timed out")
	}
}

func TestH2PinnedLoopbackCarriesPacketsAfterDialContextEnds(t *testing.T) {
	for _, scenario := range []struct {
		name, address string
		retryHello    bool
		tlsName       string
		positions     []string
		noSoak        bool
	}{
		{name: "ipv4", address: "127.0.0.1:0"},
		{name: "ipv6", address: "[::1]:0"},
		{name: "hello-retry", address: "127.0.0.1:0", retryHello: true},
		{name: "vk-name", address: "127.0.0.1:0", retryHello: true, tlsName: "vk.com"},
		{name: "google-name", address: "127.0.0.1:0", tlsName: "www.google.com"},
		{name: "vk-host", address: "127.0.0.1:0", tlsName: "vk.com", retryHello: true, positions: []string{"1", "host"}, noSoak: true},
		{name: "google-host", address: "127.0.0.1:0", tlsName: "www.google.com", retryHello: true, positions: []string{"1", "host"}, noSoak: true},
		{name: "vk-sld", address: "127.0.0.1:0", tlsName: "vk.com", retryHello: true, positions: []string{"1", "sld"}, noSoak: true},
		{name: "google-sld", address: "127.0.0.1:0", tlsName: "www.google.com", retryHello: true, positions: []string{"1", "sld"}, noSoak: true},
		{name: "vk-endhost", address: "127.0.0.1:0", tlsName: "vk.com", retryHello: true, positions: []string{"1", "endhost"}, noSoak: true},
		{name: "google-endhost", address: "127.0.0.1:0", tlsName: "www.google.com", retryHello: true, positions: []string{"1", "endhost"}, noSoak: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			clientTLS, serverTLS := masqueLoopbackTLSForName(t, scenario.tlsName)
			if scenario.retryHello {
				// The client's first share is X25519. A P-256-only TLS 1.3
				// server must request a second ClientHello before accepting it.
				clientTLS.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256}
				serverTLS.CurvePreferences = []tls.CurveID{tls.CurveP256}
				serverTLS.MinVersion = tls.VersionTLS13
			}
			fixture := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodConnect || r.ProtoMajor != 2 || r.Host != "cloudflareaccess.com:443" ||
					r.Header.Get("cf-connect-proto") != "cf-connect-ip" || r.Header.Get("pq-enabled") != "false" ||
					r.Header.Get("User-Agent") != "" {
					t.Error("CONNECT-IP request lost its HTTP2, authority, headers or client certificate")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				for {
					// The private fixture uses 32-byte IP packets and one-byte capsule fields.
					frame := make([]byte, 34)
					if _, err := io.ReadFull(r.Body, frame); err != nil {
						return
					}
					if frame[0] != 0 || frame[1] != 32 || frame[10] != 63 {
						t.Error("invalid HTTP2 DATAGRAM capsule or IP TTL")
						return
					}
					if _, err := w.Write(frame); err != nil {
						return
					}
					w.(http.Flusher).Flush()
				}
			}))
			fixture.Listener.Close()
			listener, err := net.Listen("tcp", scenario.address)
			if err != nil {
				t.Fatal(err)
			}
			fixture.Listener = listener
			fixture.EnableHTTP2, fixture.TLS = true, serverTLS
			fixture.StartTLS()
			defer fixture.Close()

			lifetime, cancelLifetime := context.WithCancel(context.Background())
			defer cancelLifetime()
			dialContext, cancelDial := context.WithCancel(context.Background())
			defer cancelDial()
			var applied atomic.Int32
			positions := scenario.positions
			if positions == nil {
				positions = []string{"1", "midsld"}
			}
			session, err := DialH2(lifetime, dialContext, &net.Dialer{}, listener.Addr().(*net.TCPAddr), clientTLS,
				&DesyncSpec{Mode: DesyncSplit, Pos: positions, OnApplied: func(segments int) {
					if segments < 3 {
						t.Errorf("incomplete ClientHello split: %d segments", segments)
					}
					applied.Add(1)
				}}, 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			wantApplications := int32(1)
			if scenario.retryHello {
				wantApplications = 2
			}
			if got := applied.Load(); got != wantApplications {
				t.Fatalf("strategy applied to %d ClientHello messages, want %d", got, wantApplications)
			}
			cancelDial()
			exchangeMasqueLoopbackPacket(t, session, 1)
			if !scenario.noSoak {
				time.Sleep(2100 * time.Millisecond)
			}
			exchangeMasqueLoopbackPacket(t, session, 2)
		})
	}
}

func TestH3PinnedLoopbackCarriesPacketsAfterDialContextEnds(t *testing.T) {
	for _, scenario := range []struct {
		name, address  string
		handshakeDelay time.Duration
		tlsName        string
	}{
		{name: "ipv4", address: "127.0.0.1:0"},
		{name: "ipv6", address: "[::1]:0"},
		{name: "delayed-handshake", address: "127.0.0.1:0", handshakeDelay: 5500 * time.Millisecond},
		{name: "vk-name", address: "127.0.0.1:0", tlsName: "vk.com"},
		{name: "google-name", address: "127.0.0.1:0", tlsName: "www.google.com"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			clientTLS, serverTLS := masqueLoopbackTLSForName(t, scenario.tlsName)
			connectTimeout := 2 * time.Second
			if scenario.handshakeDelay > 0 {
				connectTimeout = 8 * time.Second
				serverTLS.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
					timer := time.NewTimer(scenario.handshakeDelay)
					defer timer.Stop()
					select {
					case <-timer.C:
						return nil, nil
					case <-hello.Context().Done():
						return nil, hello.Context().Err()
					}
				}
			}
			listener, err := net.ListenPacket("udp", scenario.address)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			fixture := &http3.Server{TLSConfig: serverTLS, EnableDatagrams: true,
				QUICConfig: &quic.Config{HandshakeIdleTimeout: connectTimeout},
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodConnect || r.Proto != "cf-connect-ip" ||
						r.Host != "cloudflareaccess.com" || r.Header.Get("User-Agent") != "" {
						t.Error("CONNECT-IP request lost its HTTP3, protocol, authority or client certificate")
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					w.Header().Set(http3.CapsuleProtocolHeader, "?1")
					w.WriteHeader(http.StatusOK)
					stream := w.(http3.HTTPStreamer).HTTPStream()
					for {
						data, err := stream.ReceiveDatagram(r.Context())
						if err != nil {
							return
						}
						if len(data) != 33 || data[0] != 0 || data[9] != 63 {
							t.Error("invalid HTTP3 datagram or IP TTL")
							return
						}
						if err := stream.SendDatagram(data); err != nil {
							return
						}
					}
				})}
			served := make(chan error, 1)
			go func() { served <- fixture.Serve(listener) }()
			defer func() {
				fixture.Close()
				select {
				case <-served:
				case <-time.After(time.Second):
					t.Error("HTTP3 fixture did not stop")
				}
			}()
			endpoint := listener.LocalAddr().(*net.UDPAddr)
			udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: endpoint.IP})
			if err != nil {
				t.Fatal(err)
			}
			// Private decoys exercise the same strategy-aware dial as production.
			steps := []FakeStep{{Blob: bytes.Repeat([]byte{0}, 1200), Repeats: 3}}
			dialContext, cancelDial := context.WithCancel(context.Background())
			defer cancelDial()
			started := time.Now()
			session, err := DialH3WithStrategy(dialContext, udp, endpoint, clientTLS, time.Second, connectTimeout, steps, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			if scenario.handshakeDelay > 0 && time.Since(started) < scenario.handshakeDelay {
				t.Fatal("the fixture did not exercise a handshake beyond the default five-second idle limit")
			}
			cancelDial()
			exchangeMasqueLoopbackPacket(t, session, 1)
			time.Sleep(2100 * time.Millisecond)
			exchangeMasqueLoopbackPacket(t, session, 2)
		})
	}
}
