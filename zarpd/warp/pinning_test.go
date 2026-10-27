package warp

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	usqueconfig "github.com/Diniboy1123/usque/config"
)

// Actual TLS over IPv4/IPv6 loopback with an unrelated server key. This never opens TUN
// or modifies routing. Custom addresses must still fail the enrolled WARP key pin.
func TestH2RejectsAnUnpinnedLoopbackPeerAndClosesTheSocket(t *testing.T) {
	for _, scenario := range []struct{ name, address, tlsName string }{
		{name: "ipv4", address: "127.0.0.1:0"},
		{name: "ipv6", address: "[::1]:0"},
		{name: "vk-name", address: "127.0.0.1:0", tlsName: "vk.com"},
		{name: "google-name", address: "127.0.0.1:0", tlsName: "www.google.com"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			_, clientDER, _, err := generateECKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			_, _, trustedDER, err := generateECKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			serverKey, _, _, err := generateECKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			serverCert, err := generateSelfSignedCert(serverKey)
			if err != nil {
				t.Fatal(err)
			}
			config, err := TLSConfigForStrategy(&usqueconfig.Config{
				PrivateKey:     base64.StdEncoding.EncodeToString(clientDER),
				EndpointPubKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: trustedDER})),
			}, scenario.tlsName)
			if err != nil {
				t.Fatal(err)
			}
			ln, err := net.Listen("tcp", scenario.address)
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			closed := make(chan bool, 1)
			go func() {
				raw, err := ln.Accept()
				if err != nil {
					closed <- false
					return
				}
				defer raw.Close()
				_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
				peer := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{{Certificate: serverCert, PrivateKey: serverKey}}, NextProtos: []string{"h2"}})
				closed <- peer.Handshake() != nil
			}()
			session, err := DialH2(context.Background(), context.Background(), &net.Dialer{}, ln.Addr().(*net.TCPAddr), config, nil, 2*time.Second)
			if session != nil || err == nil || !strings.Contains(err.Error(), "different public key") {
				t.Fatalf("expected the enrolled WARP key pin to reject the peer: %v", err)
			}
			var phase *DialError
			if !IsPeerKeyMismatch(err) || !errors.As(err, &phase) || phase.Phase != "tls" {
				t.Fatalf("TLS trust rejection lost its type/phase: %v", err)
			}
			select {
			case rejected := <-closed:
				if !rejected {
					t.Fatal("peer handshake was not rejected")
				}
			case <-time.After(4 * time.Second):
				t.Fatal("failed pin left the peer socket open")
			}
		})
	}
}
