package relay

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	backend "github.com/feg55/zarp-macos/zarpd/proxy"

	"golang.org/x/net/proxy"
)

// Explicit opt-in and independent binary checksum. Configurations contain no TUN,
// physical binding, system DNS, production settings or remote dial destinations.
func TestPinnedXrayOuterTransports(t *testing.T) {
	binary := os.Getenv("ZARP_PARITY_XRAY")
	if binary == "" {
		t.Skip("set ZARP_PARITY_XRAY to the verified 26.9.30 PoC binary")
	}
	data, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal("cannot read pinned Xray binary")
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != "118d6c6c8c2fb913c4b2aeb056a58936016b36813c38d9b75653311787c0f93c" {
		t.Fatal("Xray PoC binary checksum mismatch")
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"127.0.0.1", "::1"} {
		for _, mode := range []string{"raw", "xhttp-h2", "xhttp-h3"} {
			for _, failure := range []string{"", "bad-pin", "bad-credential"} {
				name := mode + "/ipv4"
				if host == "::1" {
					name = mode + "/ipv6"
				}
				if failure != "" {
					name += "/" + failure
				}
				t.Run(name, func(t *testing.T) { proveXray(t, binary, host, mode, failure) })
			}
		}
	}
}

func proveXray(t *testing.T, binary, host, mode, failure string) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	certificate := testCertificate(t, directory)
	block, _ := pem.Decode([]byte(certificate))
	certificateHash := sha256.Sum256(block.Bytes)
	pin := hex.EncodeToString(certificateHash[:])
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "xray-private-https-marker") }))
	defer target.Close()
	udpTarget, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	udpAddress := udpTarget.LocalAddr().(*net.UDPAddr).AddrPort()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 2048)
		for {
			n, peer, err := udpTarget.ReadFromUDPAddrPort(buffer)
			if err != nil {
				return
			}
			_, _ = udpTarget.WriteToUDPAddrPort(buffer[:n], peer)
		}
	}()
	defer func() { udpTarget.Close(); <-done }()
	targetAddress := netip.MustParseAddrPort(target.Listener.Addr().String())
	alpn := []string{"http/1.1"}
	network := "raw"
	if mode != "raw" {
		network = "xhttp"
		alpn = []string{"h2"}
	}
	if mode == "xhttp-h3" {
		alpn = []string{"h3"}
	}
	observedALPN := alpn
	if mode == "xhttp-h2" {
		// The pinned HTTP/2 transport offers http/1.1 too. The server allows only h2,
		// so the real transfer negotiates h2; do not report an exact h2-only offer.
		observedALPN = []string{"h2", "http/1.1"}
	}
	serverPort := 0
	if mode == "xhttp-h3" {
		socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(host)})
		if err != nil {
			t.Fatal(err)
		}
		serverPort = socket.LocalAddr().(*net.UDPAddr).Port
		socket.Close()
	} else {
		listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
		if err != nil {
			t.Fatal(err)
		}
		serverPort = listener.Addr().(*net.TCPAddr).Port
		listener.Close()
	}
	secret := sessionSecret(t)
	credential := fmt.Sprintf("%s-%s-4%s-a%s-%s", secret[:8], secret[8:12], secret[13:16], secret[17:20], secret[20:32])
	probeSecret, relaySecret := sessionSecret(t), sessionSecret(t)
	serverTLS := map[string]any{"alpn": alpn, "certificates": []any{map[string]any{"certificateFile": filepath.Join(directory, "cert.pem"), "keyFile": filepath.Join(directory, "key.pem"), "oneTimeLoading": true}}}
	serverStream := map[string]any{"network": network, "security": "tls", "tlsSettings": serverTLS}
	if network == "xhttp" {
		serverStream["xhttpSettings"] = map[string]any{"path": "/private-poc", "mode": "stream-one"}
	}
	server := map[string]any{"log": map[string]any{"loglevel": "debug"}, "inbounds": []any{map[string]any{"listen": host, "port": serverPort, "protocol": "vless", "settings": map[string]any{"clients": []any{map[string]any{"id": credential}}, "decryption": "none"}, "streamSettings": serverStream}}, "outbounds": []any{map[string]any{"tag": "block", "protocol": "blackhole"}, map[string]any{"tag": "direct", "protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.1/32"}, "port": fmt.Sprintf("%d,%d", targetAddress.Port(), udpAddress.Port())}, map[string]any{"action": "block"}}}}}, "routing": map[string]any{"domainStrategy": "AsIs", "rules": []any{map[string]any{"type": "field", "ip": []string{"127.0.0.1/32"}, "port": fmt.Sprintf("%d,%d", targetAddress.Port(), udpAddress.Port()), "outboundTag": "direct"}}}}
	readyPort := serverPort
	if mode == "xhttp-h3" {
		readyPort = 0
	}
	startEngine(t, ctx, binary, directory, "server", server, readyPort)
	fixed := netip.MustParseAddrPort(net.JoinHostPort(host, strconv.Itoa(serverPort)))
	tcpObserved := make(chan Hello, 16)
	udpObserved := make(chan struct{}, 16)
	relayAddress := ""
	var ownedRelay backend.OwnedResource
	if mode == "xhttp-h3" {
		r, err := StartUDP(ctx, UDPConfig{Target: fixed, Username: "relay", Password: relaySecret, Lifetime: 15 * time.Second, Fake: []byte("invalid-xray-loopback-fake"), Observe: func(source netip.AddrPort, fake, real int) {
			if source.Addr().IsLoopback() && fake > 0 && real >= 1200 {
				udpObserved <- struct{}{}
			}
		}})
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		ownedRelay = r
		relayAddress = r.Address()
	} else {
		r, err := StartTCP(ctx, TCPConfig{Target: fixed, ServerName: "outer.example.test", Username: "relay", Password: relaySecret, Lifetime: 15 * time.Second, Observe: func(hello Hello, lengths []int) {
			if len(lengths) == 3 && lengths[0] == 1 && lengths[1] == hello.HostOffset-1 {
				tcpObserved <- hello
			}
		}})
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		ownedRelay = r
		relayAddress = r.Address()
	}
	if failure == "bad-pin" {
		pin = strings.Repeat("0", 64)
	}
	outboundCredential := credential
	if failure == "bad-credential" {
		outboundCredential = "00000000-0000-4000-a000-000000000001"
	}
	clientPort := localPort(t)
	selected := backend.VLESSTLS
	if mode == "xhttp-h2" {
		selected = backend.XHTTPH2
	} else if mode == "xhttp-h3" {
		selected = backend.XHTTPH3
	}
	startSupervisedClient(t, ctx, binary, backend.LoopbackPlan{Engine: backend.Xray, Protocol: selected,
		Target: fixed, Relay: netip.MustParseAddrPort(relayAddress),
		Listen: netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", clientPort)), ServerName: "outer.example.test",
		Pin: pin, Credential: outboundCredential, RelayUser: "relay", RelayPassword: relaySecret,
		ProbeUser: "probe", ProbePassword: probeSecret}, ownedRelay)
	roots := x509.NewCertPool()
	roots.AddCert(target.Certificate())
	flows := 2
	if failure != "" {
		flows = 1
	}
	for i := 0; i < flows; i++ {
		dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", clientPort), &proxy.Auth{User: "probe", Password: probeSecret}, &net.Dialer{Timeout: 3 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		transport := &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: roots}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.(proxy.ContextDialer).DialContext(ctx, network, address)
		}}
		request, _ := http.NewRequestWithContext(ctx, "GET", target.URL, nil)
		response, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Do(request)
		if failure != "" {
			transport.CloseIdleConnections()
			if err == nil {
				response.Body.Close()
				t.Fatal("invalid Xray pin/credential carried HTTPS")
			}
			if len(tcpObserved)+len(udpObserved) == 0 {
				t.Fatal("negative case failed before reaching the selected outer relay")
			}
			t.Log("invalid pin/credential rejected transfer")
			return
		}
		if err != nil {
			t.Fatalf("real HTTPS transfer failed through Xray outer detour (tcp_observations=%d udp_observations=%d): %v", len(tcpObserved), len(udpObserved), err)
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 128))
		response.Body.Close()
		transport.CloseIdleConnections()
		if err != nil || string(body) != "xray-private-https-marker" {
			t.Fatal("missing actual HTTPS marker")
		}
		if mode == "raw" || i == 0 {
			if mode == "xhttp-h3" {
				select {
				case <-udpObserved:
				case <-time.After(time.Second):
					t.Fatal("XHTTP H3 bypassed outer UDP fake relay")
				}
			} else {
				select {
				case hello := <-tcpObserved:
					if hello.ServerName != "outer.example.test" || !slices.Equal(hello.ALPN, observedALPN) {
						t.Fatalf("wrong outer SNI/ALPN: SNI matches=%t, ALPN=%v", hello.ServerName == "outer.example.test", hello.ALPN)
					}
				case <-time.After(time.Second):
					t.Fatal("Xray outer TLS bypassed split relay")
				}
			}
		}
	}
	_, socket := associate(t, fmt.Sprintf("127.0.0.1:%d", clientPort), "probe", probeSecret)
	if _, err := socket.Write(encodeUDP(udpAddress, []byte("xray-private-udp-marker"))); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 2048)
	n, err := socket.Read(buffer)
	if err != nil {
		t.Fatal("Xray real UDP transfer failed")
	}
	payload, ok := decodeUDP(buffer[:n], udpAddress)
	if !ok || string(payload) != "xray-private-udp-marker" {
		t.Fatal("missing actual UDP marker")
	}
	if mode == "raw" {
		select {
		case hello := <-tcpObserved:
			if hello.ServerName != "outer.example.test" || !slices.Equal(hello.ALPN, observedALPN) {
				t.Fatal("UDP payload used the wrong outer handshake")
			}
		case <-time.After(time.Second):
			t.Fatal("new outer flow carrying UDP bypassed the splitter")
		}
	}
	t.Log("real HTTPS and UDP payloads verified through pinned Xray outer detour; pooled XHTTP requests are not counted as new outer handshakes; packet boundaries/ISP effects pending")
}
