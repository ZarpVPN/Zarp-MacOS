package warp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// Observe the real socket, independently of the fake sender's callbacks. The
// fixture only sees fresh numeric loopback flows and private invalid decoys.
type retryPacketObserver struct {
	net.PacketConn
	mu      sync.Mutex
	pending int
	bursts  map[string]int
	sources map[string]bool
}

var retryFake = append([]byte("zarp-private-retry-decoy"), make([]byte, 1176)...)

func (p *retryPacketObserver) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, addr, err := p.PacketConn.ReadFrom(b)
		if err != nil {
			return n, addr, err
		}
		p.mu.Lock()
		p.sources[addr.String()] = true
		if bytes.Equal(b[:n], retryFake) {
			p.pending++
			p.mu.Unlock()
			continue
		}
		// QUIC v1 Initial: the high nibble and CID lengths are not protected.
		if n >= 7 && b[0]&0xf0 == 0xc0 && binary.BigEndian.Uint32(b[1:5]) == 1 {
			length := int(b[5])
			if length > 0 && length <= 20 && 6+length <= n {
				id := string(b[6 : 6+length])
				if _, seen := p.bursts[id]; !seen {
					p.bursts[id] = p.pending
					p.pending = 0
				}
			}
		}
		p.mu.Unlock()
		return n, addr, nil
	}
}

func TestH3FakesPrecedeEachRetryInitialOnOriginalTuple(t *testing.T) {
	clientTLS, serverTLS := masqueLoopbackTLS(t)
	clientTLS.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256}
	serverTLS.CurvePreferences = []tls.CurveID{tls.CurveP256}
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	observer := &retryPacketObserver{PacketConn: listener, bursts: map[string]int{}, sources: map[string]bool{}}
	fixture := &http3.Server{TLSConfig: serverTLS, EnableDatagrams: true, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(http3.CapsuleProtocolHeader, "?1")
		w.WriteHeader(http.StatusOK)
		stream := w.(http3.HTTPStreamer).HTTPStream()
		for {
			data, err := stream.ReceiveDatagram(r.Context())
			if err != nil {
				return
			}
			if err := stream.SendDatagram(data); err != nil {
				return
			}
		}
	})}
	served := make(chan error, 1)
	go func() { served <- fixture.Serve(observer) }()
	defer func() {
		fixture.Close()
		select {
		case <-served:
		case <-time.After(time.Second):
			t.Error("retry fixture did not stop")
		}
	}()
	endpoint := listener.LocalAddr().(*net.UDPAddr)
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	steps := []FakeStep{{Blob: retryFake, Repeats: 3}}
	session, err := DialH3WithStrategy(context.Background(), udp, endpoint, clientTLS, time.Second, 3*time.Second, steps, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	exchangeMasqueLoopbackPacket(t, session, 1)
	observer.mu.Lock()
	defer observer.mu.Unlock()
	if len(observer.sources) != 1 {
		t.Fatalf("fakes and real Initial used %d source tuples", len(observer.sources))
	}
	if len(observer.bursts) < 2 {
		t.Fatalf("fixture did not exercise a retry Initial: %d flights", len(observer.bursts))
	}
	for _, packets := range observer.bursts {
		if packets != 3 {
			t.Fatalf("new Initial was preceded by %d fake packets, want 3", packets)
		}
	}
}
