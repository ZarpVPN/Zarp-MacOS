package relay

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/feg55/zarp-macos/zarpd/connection"
	backend "github.com/feg55/zarp-macos/zarpd/proxy"
	"github.com/feg55/zarp-macos/zarpd/socksclient"
	"github.com/feg55/zarp-macos/zarpd/warp"
)

// The actual product compiler, production guardian and outer strategy carry
// private HTTPS and UDP. There is no TUN, public destination or route mutation.
func TestPinnedProductServerRuntime(t *testing.T) {
	sing, xray := os.Getenv("ZARP_PARITY_SING_BOX"), os.Getenv("ZARP_PARITY_XRAY")
	if sing == "" || xray == "" {
		t.Skip("requires both pinned loopback fixture engines")
	}
	programs := t.TempDir()
	helper := buildLoopbackGuardian(t, programs)
	if err := os.Rename(helper, filepath.Join(programs, "zarp-backend-guardian")); err != nil {
		t.Fatal(err)
	}
	helperBytes, err := os.ReadFile(filepath.Join(programs, "zarp-backend-guardian"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(helperBytes)
	inventory := t.TempDir()
	for relative, original := range map[string]string{"sing-box-1.13.14/sing-box": sing, "xray-26.9.30/xray": xray} {
		data, err := os.ReadFile(original)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(inventory, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0700); err != nil {
			t.Fatal(err)
		}
	}
	launcher, err := backend.NewServerGuardianLauncher(programs, hex.EncodeToString(digest[:]), inventory)
	if err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []string{"vless", "trojan", "hysteria2", "xhttp"} {
		modes := []string{""}
		if protocol == "xhttp" {
			modes = []string{"auto", "packet-up", "stream-up", "stream-one", "h3", "auto-extra", "packet-up-download"}
		}
		for _, mode := range modes {
			t.Run(protocol+"/"+mode, func(t *testing.T) { productServerFlow(t, launcher, sing, xray, protocol, mode, false) })
		}
	}
	t.Run("vless/bad-credential", func(t *testing.T) { productServerFlow(t, launcher, sing, xray, "vless", "", true) })
	t.Run("xhttp/bad-credential", func(t *testing.T) { productServerFlow(t, launcher, sing, xray, "xhttp", "stream-one", true) })
}

func productServerFlow(t *testing.T, launcher *backend.GuardianLauncher, sing, xray, protocol, mode string, badCredential bool) {
	t.Helper()
	directory := t.TempDir()
	soak := os.Getenv("ZARP_PARITY_SERVER_SOAK") == "1" && protocol == "vless" && mode == "" && !badCredential
	duration := 20 * time.Second
	if soak {
		duration = 155 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	certificate := testCertificate(t, directory)
	block, _ := pem.Decode([]byte(certificate))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	certificateHash := sha256.Sum256(block.Bytes)
	publicHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "product-server-https") }))
	defer target.Close()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	var udpReceived, udpReplied atomic.Uint64
	udpDone := make(chan struct{})
	go func() {
		defer close(udpDone)
		buffer := make([]byte, 2048)
		for {
			n, peer, err := udp.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			udpReceived.Add(1)
			if count, err := udp.WriteToUDP(buffer[:n], peer); err == nil && count == n {
				udpReplied.Add(1)
			}
		}
	}()
	defer func() { udp.Close(); <-udpDone }()
	inner := netip.MustParseAddrPort(target.Listener.Addr().String())
	udpAddress := udp.LocalAddr().(*net.UDPAddr).AddrPort()
	credential := "00000000-0000-4000-a000-000000000001"
	if protocol == "trojan" || protocol == "hysteria2" {
		credential = sessionSecret(t)
	}
	serverPort := localPort(t)
	useUDP := protocol == "hysteria2" || mode == "h3"
	if useUDP {
		socket, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if e != nil {
			t.Fatal(e)
		}
		serverPort = socket.LocalAddr().(*net.UDPAddr).Port
		socket.Close()
	}
	alpn := []string{"http/1.1"}
	if protocol == "xhttp" {
		alpn = []string{"h2"}
	}
	if useUDP {
		alpn = []string{"h3"}
	}
	profile := connection.Profile{Host: "127.0.0.1", Port: serverPort, Protocol: protocol, Credential: connection.Credential{Kind: "password", Value: credential}, Transport: "tcp", Security: "tls", ServerName: stringPointer("outer.example.test"), ALPN: alpn, Flow: "none"}
	if protocol == "vless" || protocol == "xhttp" {
		profile.Protocol = "vless"
		profile.Credential.Kind = "uuid"
	}
	if protocol == "hysteria2" {
		profile.Transport = "quic"
	}
	binary := sing
	var server map[string]any
	if protocol == "xhttp" {
		binary = xray
		profile.Transport = "xhttp"
		profile.Path = stringPointer("/product")
		if mode == "h3" {
			profile.XHTTPMode = stringPointer("stream-one")
		} else if mode == "auto-extra" {
			profile.XHTTPMode = stringPointer("auto")
			profile.XHTTPExtra = stringPointer(`{"xPaddingBytes":"10-20","xmux":{"maxConcurrency":"16-32"}}`)
		} else if mode == "packet-up-download" {
			profile.XHTTPMode = stringPointer("packet-up")
			profile.XHTTPExtra = stringPointer(`{"downloadSettings":{"address":"127.0.0.1","network":"xhttp","security":"tls","tlsSettings":{"serverName":"outer.example.test","alpn":["h2"]},"xhttpSettings":{"path":"/product","mode":"packet-up"}}}`)
		} else {
			profile.XHTTPMode = stringPointer(mode)
		}
		server = map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": serverPort, "protocol": "vless", "settings": map[string]any{"clients": []any{map[string]any{"id": credential}}, "decryption": "none"}, "streamSettings": map[string]any{"network": "xhttp", "security": "tls", "xhttpSettings": map[string]any{"path": "/product", "mode": "auto"}, "tlsSettings": map[string]any{"alpn": alpn, "certificates": []any{map[string]any{"certificateFile": filepath.Join(directory, "cert.pem"), "keyFile": filepath.Join(directory, "key.pem")}}}}}}, "outbounds": []any{map[string]any{"tag": "block", "protocol": "blackhole"}, map[string]any{"tag": "direct", "protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.1/32"}, "port": fmt.Sprintf("%d,%d", inner.Port(), udpAddress.Port())}, map[string]any{"action": "block"}}}}}, "routing": map[string]any{"rules": []any{map[string]any{"type": "field", "ip": []string{"127.0.0.1/32"}, "port": fmt.Sprintf("%d,%d", inner.Port(), udpAddress.Port()), "outboundTag": "direct"}}}}
	} else {
		field := "password"
		if protocol == "vless" {
			field = "uuid"
		}
		server = map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{map[string]any{"type": protocol, "listen": "127.0.0.1", "listen_port": serverPort, "users": []any{map[string]any{field: credential}}, "tls": map[string]any{"enabled": true, "certificate_path": filepath.Join(directory, "cert.pem"), "key_path": filepath.Join(directory, "key.pem"), "alpn": alpn}}}, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}, "route": map[string]any{"rules": []any{map[string]any{"ip_cidr": []string{"127.0.0.1/32"}, "port": []int{int(inner.Port()), int(udpAddress.Port())}, "action": "route", "outbound": "direct"}, map[string]any{"action": "reject"}}, "final": "direct"}}
	}
	ready := serverPort
	if mode == "auto-extra" {
		// XHTTP validates padding against the server's advertised range. This
		// fixture must match its custom client profile instead of server defaults.
		server["inbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)["xhttpSettings"].(map[string]any)["xPaddingBytes"] = "10-20"
	}
	if useUDP {
		ready = 0
	}
	startEngine(t, ctx, binary, directory, "server", server, ready)
	outerCfg := OuterConfig{Target: netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", serverPort)), ServerName: "outer.example.test", Username: "relay", Password: sessionSecret(t), UDP: useUDP}
	if useUDP {
		outerCfg.FakeSteps = []warp.FakeStep{{Blob: []byte("private-product-fake"), Repeats: 2}}
	} else {
		outerCfg.Desync = &warp.DesyncSpec{Mode: warp.DesyncSplit, Pos: []string{"1", "host"}}
	}
	outer, err := StartOuter(ctx, outerCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer outer.CloseBounded(context.Background())
	if badCredential {
		if profile.Credential.Kind == "uuid" {
			profile.Credential.Value = "00000000-0000-4000-a000-000000000002"
		} else {
			profile.Credential.Value = "wrong-private-password"
		}
	}
	plan := backend.ServerPlan{Profile: profile, Target: outerCfg.Target, Relay: outer.Address(), Listen: netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", localPort(t))), RelayUser: outerCfg.Username, RelayPassword: outerCfg.Password, ProbeUser: "probe", ProbePassword: sessionSecret(t), Pin: base64.StdEncoding.EncodeToString(publicHash[:])}
	if protocol == "xhttp" {
		plan.Pin = hex.EncodeToString(certificateHash[:])
	}
	session, err := launcher.StartServer(ctx, plan, backend.Limits{StartupTimeout: 5 * time.Second, StopGrace: time.Second, Lifetime: 30 * time.Second})
	if err != nil {
		t.Fatal("product guardian startup:", err)
	}
	defer func() {
		if err := session.Close(); err != nil {
			t.Error("product cleanup:", err)
		}
	}()
	client := socksclient.Client{Address: plan.Listen, Username: plan.ProbeUser, Password: plan.ProbePassword}
	roots := x509.NewCertPool()
	roots.AddCert(target.Certificate())
	transport := &http.Transport{DialContext: client.DialContext, TLSClientConfig: &tls.Config{RootCAs: roots}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport, Timeout: 4 * time.Second}).Get(target.URL)
	if badCredential {
		if err == nil {
			response.Body.Close()
			t.Fatal("wrong credential carried authenticated HTTPS")
		}
		if outer.Statistics().AppliedFlows == 0 {
			t.Fatal("failure occurred before the outer strategy")
		}
		return
	}
	if err != nil {
		t.Fatal("product HTTPS transfer:", err)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 128))
	response.Body.Close()
	if err != nil || string(body) != "product-server-https" {
		t.Fatal("HTTPS payload mismatch")
	}
	udpFlow, err := client.DialContext(ctx, "udp", udpAddress.String())
	if err != nil {
		t.Fatal(err)
	}
	defer udpFlow.Close()
	udpFlow.SetDeadline(time.Now().Add(3 * time.Second))
	payload := []byte("product-private-dns-udp")
	if _, err = udpFlow.Write(payload); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 128)
	n, err := udpFlow.Read(buffer)
	if err != nil || string(buffer[:n]) != string(payload) {
		backendEnded := false
		select {
		case <-session.Done():
			backendEnded = true
		default:
		}
		t.Fatalf("UDP payload mismatch: %v; fixture_received=%d fixture_replied=%d backend_ended=%v outer=%+v",
			err, udpReceived.Load(), udpReplied.Load(), backendEnded, outer.Statistics())
	}
	if outer.Statistics().AppliedFlows == 0 {
		t.Fatal("traffic bypassed required outer strategy")
	}
	if useUDP && outer.Statistics().FakePackets < 2 {
		t.Fatal("missing outer fake packets")
	}
	if err := session.RenewLease(); err != nil {
		t.Fatal("production lease renewal:", err)
	}
	if soak {
		until := time.Now().Add(130 * time.Second)
		for time.Now().Before(until) {
			select {
			case <-ctx.Done():
				t.Fatal("private product soak deadline")
			case <-time.After(10 * time.Second):
			}
			if err := session.RenewLease(); err != nil {
				t.Fatal("product session ended during renewable soak:", err)
			}
		}
		response, err := (&http.Client{Transport: transport, Timeout: 4 * time.Second}).Get(target.URL)
		if err != nil {
			t.Fatal("HTTPS failed after original PoC lifetime:", err)
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 128))
		response.Body.Close()
		if err != nil || string(body) != "product-server-https" {
			t.Fatal("late product HTTPS mismatch")
		}
		t.Log("real HTTPS and renewable ownership survived the original two-minute PoC cap")
	}
}

func stringPointer(value string) *string { return &value }
