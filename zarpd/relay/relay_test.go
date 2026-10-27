package relay

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

// Capture a real Go TLS ClientHello without completing TLS or using a network interface.
func captureHello(t *testing.T, names ...string) Hello {
	t.Helper()
	name := "outer.example.test"
	if len(names) == 1 {
		name = names[0]
	}
	client, peer := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn := tls.Client(client, &tls.Config{ServerName: name, NextProtos: []string{"h2", "http/1.1"}})
		_ = conn.Handshake()
		conn.Close()
	}()
	_ = peer.SetDeadline(time.Now().Add(2 * time.Second))
	hello, err := readClientHello(peer, len(names) == 1)
	peer.Close()
	<-done
	if err != nil {
		t.Fatal(err)
	}
	return hello
}

func TestNumericSplitWithoutSNIRefusesUnappliedHostMarkers(t *testing.T) {
	hello := captureHello(t, "192.0.2.1")
	if hello.ServerName != "" || len(hello.splitPositions([]string{"1"})) != 1 {
		t.Fatal("numeric TLS split requires no SNI")
	}
	if len(hello.splitPositions([]string{"1", "host"})) != 0 {
		t.Fatal("missing requested host marker was silently ignored")
	}
	if _, err := ReadClientHello(bytes.NewReader(hello.Wire)); err == nil {
		t.Fatal("strict loopback contract changed")
	}
}

type byteReader struct{ io.Reader }

func (r byteReader) Read(p []byte) (int, error) { return r.Reader.Read(p[:1]) }

func TestHelloFragmentationAndWireMapping(t *testing.T) {
	original := captureHello(t)
	if original.ServerName != "outer.example.test" || len(original.ALPN) != 2 || original.ALPN[0] != "h2" {
		t.Fatal("lost outer TLS metadata")
	}
	// Split inside SNI. Both TLS record boundaries and one-byte reads must be preserved.
	body := original.Wire[5:]
	cut := original.HostOffset - 5 + 3
	var wire []byte
	for _, part := range [][]byte{body[:2], body[2:cut], body[cut:]} {
		header := []byte{22, 3, 1, 0, 0}
		binary.BigEndian.PutUint16(header[3:], uint16(len(part)))
		wire = append(wire, header...)
		wire = append(wire, part...)
	}
	hello, err := ReadClientHello(byteReader{bytes.NewReader(wire)})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hello.Wire, wire) || hello.ServerName != original.ServerName || !bytes.Equal(wire[hello.HostOffset:hello.HostOffset+3], []byte("out")) {
		t.Fatal("record mapping changed bytes or SNI offset")
	}
	for _, invalid := range [][]byte{nil, wire[:len(wire)-1], {23, 3, 1, 0, 1, 0}, {22, 3, 1, 255, 255}} {
		if _, err := ReadClientHello(bytes.NewReader(invalid)); err == nil {
			t.Fatal("accepted malformed hello")
		}
	}
}

func TestRelayFixedTargetAndCancellation(t *testing.T) {
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	ctx, cancel := context.WithCancel(context.Background())
	r, err := StartTCP(ctx, TCPConfig{Target: netip.MustParseAddrPort(target.Addr().String()), ServerName: "outer.example.test", Username: "test", Password: "private", Lifetime: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	wrong, _ := proxy.SOCKS5("tcp", r.Address(), &proxy.Auth{User: "test", Password: "wrong"}, &net.Dialer{Timeout: time.Second})
	if conn, err := wrong.Dial("tcp", target.Addr().String()); err == nil {
		conn.Close()
		t.Fatal("accepted wrong credential")
	}
	dialer, _ := proxy.SOCKS5("tcp", r.Address(), &proxy.Auth{User: "test", Password: "private"}, &net.Dialer{Timeout: time.Second})
	if conn, err := dialer.Dial("tcp", "127.0.0.1:1"); err == nil {
		conn.Close()
		t.Fatal("accepted arbitrary destination")
	}
	conn, err := dialer.Dial("tcp", target.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	accepted, err := target.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	cancel()
	done := make(chan struct{})
	go func() { r.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancellation left worker blocked before ClientHello")
	}
	_ = accepted.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := accepted.Read(make([]byte, 1)); err == nil {
		t.Fatal("upstream still open")
	}
}

func TestPrivateEngineDiagnosticsBoundedAndRedacted(t *testing.T) {
	log := &boundedEngineLog{}
	var workers sync.WaitGroup
	for _, event := range []string{"accepted", "peer cert is unrecognized", "failed to"} {
		workers.Add(1)
		go func(event string) {
			defer workers.Done()
			payload := []byte(event + " private-password private-uuid\n")
			for i := 0; i < 2000; i++ {
				n, err := log.Write(payload)
				if err != nil || n != len(payload) {
					t.Error("diagnostic writer blocked or returned a short write")
					return
				}
			}
		}(event)
	}
	workers.Wait()
	if log.data.Len() > 32768 {
		t.Fatal("raw private diagnostics exceeded limit")
	}
	categories := fmt.Sprint(log.categories())
	if strings.Contains(categories, "private") || len(log.categories()) == 0 {
		t.Fatal("credential-bearing diagnostics escaped category filter")
	}
}
