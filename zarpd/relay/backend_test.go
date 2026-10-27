package relay

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/feg55/zarp-macos/zarpd/connection"
	backend "github.com/feg55/zarp-macos/zarpd/proxy"

	"golang.org/x/net/proxy"
)

// Explicit opt-in executes only a checksum-pinned engine with generated loopback configs.
// No TUN inbound, system DNS, physical-interface binding or production credentials exist here.
func TestPinnedBackendOuterTransports(t *testing.T) {
	binary := os.Getenv("ZARP_PARITY_SING_BOX")
	if binary == "" {
		t.Skip("set ZARP_PARITY_SING_BOX to the verified 1.13.14 PoC binary")
	}
	data, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal("cannot read pinned PoC binary")
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != "813d8effd02a19572a8d75aef29fc073101404ca535b2496be86f21827c7684d" {
		t.Fatal("PoC binary checksum mismatch")
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []string{"vless", "trojan", "hysteria2"} {
		for _, failure := range []string{"", "good-pin", "bad-pin", "bad-credential"} {
			name := protocol + "/success"
			if failure != "" {
				name = protocol + "/" + failure
			}
			t.Run(name, func(t *testing.T) { proveBackend(t, binary, protocol, failure, "127.0.0.1") })
		}
		for _, failure := range []string{"", "good-pin", "bad-pin", "bad-credential"} {
			name := protocol + "/ipv6-success"
			if failure != "" {
				name = protocol + "/ipv6-" + failure
			}
			t.Run(name, func(t *testing.T) { proveBackend(t, binary, protocol, failure, "::1") })
		}
		if protocol == "hysteria2" {
			t.Run(protocol+"/fresh-session", func(t *testing.T) { proveBackend(t, binary, protocol, "", "127.0.0.1") })
		}
	}
	for _, protocol := range []string{"vless", "trojan"} {
		for _, transport := range []backend.HTTPTransport{backend.WebSocket, backend.GRPC, backend.HTTPUpgrade} {
			for _, host := range []string{"127.0.0.1", "::1"} {
				for _, failure := range []string{"good-pin", "bad-pin", "bad-credential"} {
					t.Run(protocol+"/"+string(transport)+"/"+host+"/"+failure, func(t *testing.T) { proveBackend(t, binary, protocol, failure, host, transport) })
				}
				if transport == backend.GRPC {
					t.Run(protocol+"/grpc/"+host+"/fresh-session", func(t *testing.T) { proveBackend(t, binary, protocol, "fresh-session", host, transport) })
				}
			}
		}
	}
	for _, variant := range []string{"vision", "reality", "reality-vision", "salamander"} {
		protocol := "vless"
		failures := []string{"good-pin", "bad-pin", "bad-credential", "bad-flow"}
		if variant == "salamander" {
			protocol = "hysteria2"
			failures = []string{"good-pin", "bad-pin", "bad-credential", "bad-obfs", "missing-obfs"}
		} else if strings.HasPrefix(variant, "reality") {
			failures = []string{"good-key", "bad-key", "bad-short-id", "bad-credential"}
		}
		for _, host := range []string{"127.0.0.1", "::1"} {
			for _, failure := range failures {
				t.Run(variant+"/"+host+"/"+failure, func(t *testing.T) {
					proveBackendOptions(t, binary, protocol, failure, host, backendOptions{variant: variant})
				})
			}
			t.Run(variant+"/"+host+"/fresh-session", func(t *testing.T) {
				proveBackendOptions(t, binary, protocol, "fresh-session", host, backendOptions{variant: variant})
			})
		}
	}
	for _, protocol := range []string{"vless", "trojan"} {
		for _, host := range []string{"127.0.0.1", "::1"} {
			for _, failure := range []string{"good-pin", "bad-pin", "bad-credential", "fresh-session"} {
				t.Run(protocol+"-fingerprint/"+host+"/"+failure, func(t *testing.T) {
					proveBackendOptions(t, binary, protocol, failure, host, backendOptions{variant: "fingerprint"})
				})
			}
		}
	}
	for _, host := range []string{"127.0.0.1", "::1"} {
		for _, failure := range []string{"good-pin", "bad-pin"} {
			t.Run("udp-hop-limit/"+host+"/"+failure, func(t *testing.T) {
				proveBackendOptions(t, binary, "hysteria2", failure, host, backendOptions{fakeHopLimit: 1})
			})
		}
	}
	guardianDirectory := t.TempDir()
	guardianBinary := ""
	for _, protocol := range []string{"vless", "hysteria2"} {
		for _, host := range []string{"127.0.0.1", "::1"} {
			modes := []string{"good", "bad-name"}
			if protocol == "hysteria2" {
				modes = []string{"good", "bad-marker"}
			}
			for _, mode := range modes {
				t.Run("owned-https-probe-"+protocol+"/"+host+"/"+mode, func(t *testing.T) {
					if guardianBinary == "" {
						guardianBinary = buildLoopbackGuardian(t, guardianDirectory)
					}
					proveBackendOptions(t, binary, protocol, "good-pin", host, backendOptions{guardianBinary: guardianBinary, guardianOwned: true, ownedProbe: mode})
				})
			}
		}
	}
	for _, protocol := range []string{"vless", "hysteria2"} {
		for _, host := range []string{"127.0.0.1", "::1"} {
			t.Run("guardian-"+protocol+"/"+host, func(t *testing.T) {
				if guardianBinary == "" {
					guardianBinary = buildLoopbackGuardian(t, guardianDirectory)
				}
				proveBackendOptions(t, binary, protocol, "good-pin", host, backendOptions{guardianBinary: guardianBinary})
			})
		}
	}
	t.Run("guardian-term-vless/127.0.0.1", func(t *testing.T) {
		if guardianBinary == "" {
			guardianBinary = buildLoopbackGuardian(t, guardianDirectory)
		}
		proveBackendOptions(t, binary, "vless", "good-pin", "127.0.0.1", backendOptions{guardianBinary: guardianBinary, guardianTerminate: true})
	})
	for _, protocol := range []string{"vless", "hysteria2"} {
		for _, host := range []string{"127.0.0.1", "::1"} {
			t.Run("guardian-owned-"+protocol+"/"+host, func(t *testing.T) {
				if guardianBinary == "" {
					guardianBinary = buildLoopbackGuardian(t, guardianDirectory)
				}
				proveBackendOptions(t, binary, protocol, "good-pin", host, backendOptions{guardianBinary: guardianBinary, guardianOwned: true})
			})
			t.Run("guardian-owner-crash-"+protocol+"/"+host, func(t *testing.T) {
				if guardianBinary == "" {
					guardianBinary = buildLoopbackGuardian(t, guardianDirectory)
				}
				proveBackendOptions(t, binary, protocol, "good-pin", host, backendOptions{guardianBinary: guardianBinary, guardianOwnerCrash: true})
			})
		}
	}
}

func localPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port
}

func testCertificate(t *testing.T, directory string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "outer.example.test"}, DNSNames: []string{"outer.example.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificate := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	for name, value := range map[string][]byte{"cert.pem": []byte(certificate), "key.pem": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})} {
		if err := os.WriteFile(filepath.Join(directory, name), value, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return certificate
}

func startEngine(t *testing.T, ctx context.Context, binary, directory, name string, config map[string]any, port int) {
	t.Helper()
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal("invalid PoC configuration")
	}
	path := filepath.Join(directory, name+".json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	// Do not print raw engine output: configuration errors can expose generated credentials.
	checkArgs, runArgs := []string{"check", "-c", path}, []string{"run", "-c", path}
	if filepath.Base(binary) == "xray" {
		checkArgs, runArgs = []string{"run", "-test", "-config", path}, []string{"run", "-config", path}
	}
	check := exec.CommandContext(ctx, binary, checkArgs...)
	// Server fixtures have the same environment boundary as the supervised client.
	// Engine configuration directories, preloads and credentials are never inherited.
	privateEnvironment := []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "TMPDIR=" + directory}
	check.Env = privateEnvironment
	if err := check.Run(); err != nil {
		t.Fatal("pinned engine rejected loopback configuration")
	}
	child := exec.CommandContext(ctx, binary, runArgs...)
	child.Env = privateEnvironment
	diagnostics := &boundedEngineLog{}
	child.Stdout = diagnostics
	child.Stderr = diagnostics
	if err := child.Start(); err != nil {
		t.Fatal("cannot start private loopback engine")
	}
	done := make(chan struct{})
	go func() { _ = child.Wait(); close(done) }()
	t.Cleanup(func() {
		// The process handle belongs to this exact Start call. No process-name matching.
		_ = child.Process.Signal(os.Interrupt)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			_ = child.Process.Kill()
			<-done
		}
		if t.Failed() && filepath.Base(binary) == "xray" {
			t.Logf("private engine %s diagnostic categories: %v", name, diagnostics.categories())
		}
	})
	if port == 0 {
		select {
		case <-done:
			t.Fatal("private UDP engine exited during startup")
		case <-ctx.Done():
			t.Fatal("private UDP engine startup cancelled")
		case <-time.After(150 * time.Millisecond):
			return
		}
	}
	listenHost := config["inbounds"].([]any)[0].(map[string]any)["listen"].(string)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(listenHost, strconv.Itoa(port)), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("loopback engine startup timed out")
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("loopback engine did not listen")
}

func startSupervisedClient(t *testing.T, ctx context.Context, binary string, plan backend.LoopbackPlan, resource backend.OwnedResource) {
	t.Helper()
	// The runner chooses a reviewed, pinned inventory, never an IPC/profile path.
	supervisor, err := backend.NewSupervisor(filepath.Dir(filepath.Dir(binary)))
	if err != nil {
		t.Fatal("private supervisor inventory unavailable")
	}
	session, err := supervisor.StartLoopbackChain(ctx, plan, backend.Limits{
		StartupTimeout: 5 * time.Second, Lifetime: 15 * time.Second, StopGrace: 200 * time.Millisecond}, resource)
	if err != nil {
		t.Fatal("private typed backend startup failed:", err)
	}
	t.Cleanup(func() {
		if err := session.Close(); err != nil || !session.Status().CleanupOK {
			t.Error("private supervised backend cleanup failed")
		}
	})
}

func startSupervisedProfileClient(t *testing.T, ctx context.Context, binary string, plan backend.LoopbackPlan, alpn []string, resource backend.OwnedResource, guardian ...string) func() {
	return startSupervisedProfileClientWithProbe(t, ctx, binary, plan, alpn, resource, nil, guardian...)
}

type ownedHTTPSProbeCase struct {
	spec     backend.LoopbackHTTPSProbe
	expected error
}

func startSupervisedProfileClientWithProbe(t *testing.T, ctx context.Context, binary string, plan backend.LoopbackPlan, alpn []string, resource backend.OwnedResource, check *ownedHTTPSProbeCase, guardian ...string) func() {
	t.Helper()
	profile := connection.Profile{Host: plan.Target.Addr().String(), Port: int(plan.Target.Port()), Protocol: "vless",
		Credential: connection.Credential{Kind: "uuid", Value: plan.Credential}, Transport: "tcp", Security: "tls",
		ServerName: &plan.ServerName, ALPN: alpn, Flow: "none"}
	if plan.Protocol == backend.TrojanTLS {
		profile.Protocol, profile.Credential.Kind = "trojan", "password"
	}
	if plan.Protocol == backend.Hysteria2TLS {
		profile.Protocol, profile.Credential.Kind, profile.Transport = "hysteria2", "password", "quic"
	}
	if plan.Flow != "" {
		profile.Flow = "vision"
	}
	if plan.Fingerprint != "" {
		profile.Fingerprint = &plan.Fingerprint
	}
	if plan.Protocol == backend.VLESSReality {
		profile.Security, profile.PublicKey, profile.ShortID = "reality", &plan.RealityPublicKey, &plan.RealityShortID
	}
	if plan.ObfsPassword != "" {
		obfs := "salamander"
		profile.Obfs, profile.ObfsPassword = &obfs, &plan.ObfsPassword
	}
	switch plan.HTTPTransport {
	case backend.WebSocket:
		profile.Transport = "ws"
	case backend.GRPC:
		profile.Transport = "grpc"
	case backend.HTTPUpgrade:
		profile.Transport = "httpUpgrade"
	}
	if plan.Path != "" {
		profile.Path = &plan.Path
	}
	if plan.HostHeader != "" {
		profile.HostHeader = &plan.HostHeader
	}
	if plan.ServiceName != "" {
		profile.ServiceName = &plan.ServiceName
	}
	wire, err := json.Marshal(profile)
	if err != nil {
		t.Fatal("private shared profile encoding failed")
	}
	decoded, err := connection.DecodeProfile(wire)
	if err != nil {
		t.Fatal("private shared profile decoding failed:", err)
	}
	access := backend.LoopbackAccess{Target: plan.Target, Relay: plan.Relay, Listen: plan.Listen,
		Pin: plan.Pin, RelayUser: plan.RelayUser, RelayPassword: plan.RelayPassword, ProbeUser: plan.ProbeUser, ProbePassword: plan.ProbePassword}
	supervisor, err := backend.NewSupervisor(filepath.Dir(filepath.Dir(binary)))
	if err != nil {
		t.Fatal("private supervisor inventory unavailable")
	}
	var owner *backend.RuntimeOwner
	if len(guardian) == 0 {
		owner = backend.NewRuntimeOwner(ctx, supervisor)
	} else {
		data, err := os.ReadFile(guardian[0])
		if err != nil {
			t.Fatal("private guardian pin unavailable")
		}
		digest := sha256.Sum256(data)
		launcher, err := backend.NewLoopbackGuardianLauncher(filepath.Dir(guardian[0]), hex.EncodeToString(digest[:]), filepath.Dir(filepath.Dir(binary)))
		if err != nil {
			t.Fatal("private guardian construction failed")
		}
		owner = backend.NewRuntimeOwner(ctx, launcher)
	}
	var closeOnce sync.Once
	cleanup := func() {
		closeOnce.Do(func() {
			if err := owner.Close(); err != nil {
				t.Error("private owned backend cleanup failed")
			}
			if snapshot, exists := owner.Snapshot(); !exists || !snapshot.Backend.CleanupOK {
				t.Error("private owned backend cleanup was not verified")
			}
		})
	}
	t.Cleanup(cleanup)
	// This synthetic fingerprint describes only the test relay's technique. It
	// does not claim that a production strategy or system frontend is available.
	technique := "loopback-poc-tcp-three-writes-v1"
	if plan.Protocol == backend.Hysteria2TLS {
		technique = "loopback-poc-udp-fake-before-real-v1"
	}
	fingerprint := sha256.Sum256([]byte(technique))
	request, disappear := context.WithCancel(ctx)
	defer disappear()
	started, err := owner.StartLoopback(request, decoded, access, hex.EncodeToString(fingerprint[:]), backend.Limits{
		StartupTimeout: 5 * time.Second, Lifetime: 15 * time.Second, StopGrace: 200 * time.Millisecond}, resource)
	if err != nil {
		t.Fatal("private shared-profile owned startup failed:", err)
	}
	disappear()
	adopted, err := owner.Adopt()
	if err != nil || adopted.RunID != started.RunID || adopted.ServerID != decoded.ID() || adopted.StrategyFingerprint != started.StrategyFingerprint {
		t.Fatal("private backend adoption failed after request client disappeared")
	}
	if err := owner.RenewLease(adopted.RunID); err != nil {
		t.Fatal("private backend lease renewal failed")
	}
	if check != nil {
		result, err := owner.ProbeLoopbackHTTPS(ctx, started.RunID, check.spec)
		if err != check.expected {
			t.Fatal("owned probe returned wrong static result", err)
		}
		if err == nil {
			if result.RunID != started.RunID || result.ServerID != decoded.ID() || result.FirstResponseMillis[0] < 1 || result.FirstResponseMillis[1] < 1 {
				t.Fatal("owned probe failed to credit the current run")
			}
		} else if result != (backend.HTTPSProbeResult{}) {
			t.Fatal("failed owned probe returned partial confirmation")
		}
		if after, err := owner.Adopt(); err != nil || after.RunID != started.RunID {
			t.Fatal("measurement replaced or stopped its owner")
		}
	}
	// The callers now verify real HTTPS/UDP after request detachment and adoption.
	return cleanup
}

func proveBackend(t *testing.T, binary, protocol, failure, serverHost string, transports ...backend.HTTPTransport) {
	var options backendOptions
	if len(transports) > 0 {
		options.transport = transports[0]
	}
	proveBackendOptions(t, binary, protocol, failure, serverHost, options)
}

type backendOptions struct {
	transport          backend.HTTPTransport
	variant            string
	guardianBinary     string
	guardianTerminate  bool
	guardianOwned      bool
	guardianOwnerCrash bool
	fakeHopLimit       int
	ownedProbe         string
}

func proveBackendOptions(t *testing.T, binary, protocol, failure, serverHost string, options backendOptions) {
	selectedTransport := options.transport
	vision := options.variant == "vision" || options.variant == "reality-vision"
	reality := strings.HasPrefix(options.variant, "reality")
	salamander := options.variant == "salamander"
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var stopGuardian func()
	certificate := testCertificate(t, directory)
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "real-private-https-marker") }))
	defer target.Close()
	serverPort, clientPort := localPort(t), localPort(t)
	if serverHost == "::1" {
		listener, err := net.Listen("tcp6", "[::1]:0")
		if err != nil {
			t.Fatal(err)
		}
		serverPort = listener.Addr().(*net.TCPAddr).Port
		listener.Close()
	}
	alpn := []string{"http/1.1"}
	if selectedTransport == backend.GRPC {
		alpn = []string{"h2"}
	}
	if reality {
		alpn = []string{"h2", "http/1.1"}
	}
	readyPort := serverPort
	if protocol == "hysteria2" {
		socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(serverHost)})
		if err != nil {
			t.Fatal(err)
		}
		serverPort = socket.LocalAddr().(*net.UDPAddr).Port
		socket.Close()
		readyPort = 0
		alpn = []string{"h3"}
	}
	targetAddress := netip.MustParseAddrPort(target.Listener.Addr().String())
	udpTarget, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpTarget.Close()
	udpAddress := udpTarget.LocalAddr().(*net.UDPAddr).AddrPort()
	udpDone := make(chan struct{})
	go func() {
		defer close(udpDone)
		buffer := make([]byte, 2048)
		for {
			n, peer, err := udpTarget.ReadFromUDPAddrPort(buffer)
			if err != nil {
				return
			}
			_, _ = udpTarget.WriteToUDPAddrPort(buffer[:n], peer)
		}
	}()
	defer func() { udpTarget.Close(); <-udpDone }()
	safeRules := []any{map[string]any{"ip_cidr": []string{"127.0.0.1/32"}, "port": []int{int(targetAddress.Port()), int(udpAddress.Port())}, "action": "route", "outbound": "direct"}, map[string]any{"action": "reject"}}
	credential := sessionSecret(t)
	relaySecret, probeSecret := sessionSecret(t), sessionSecret(t)
	credentialField := "password"
	if protocol == "vless" {
		credential = fmt.Sprintf("%s-%s-4%s-a%s-%s", credential[:8], credential[8:12], credential[13:16], credential[17:20], credential[20:32])
		credentialField = "uuid"
	}
	server := map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{map[string]any{"type": protocol, "listen": serverHost, "listen_port": serverPort, "users": []any{map[string]any{credentialField: credential}}, "tls": map[string]any{"enabled": true, "certificate_path": filepath.Join(directory, "cert.pem"), "key_path": filepath.Join(directory, "key.pem"), "alpn": alpn}}}, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}, "route": map[string]any{"rules": safeRules, "final": "direct"}}
	inbound := server["inbounds"].([]any)[0].(map[string]any)
	obfsPassword, publicKey, shortID := "", "", ""
	if vision {
		inbound["users"].([]any)[0].(map[string]any)["flow"] = "xtls-rprx-vision"
	}
	if salamander {
		obfsPassword = sessionSecret(t)
		inbound["obfs"] = map[string]any{"type": "salamander", "password": obfsPassword}
	}
	if reality {
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal("private Reality key generation failed")
		}
		publicKey, shortID = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), sessionSecret(t)[:16]
		// Camouflage handshakes and fallback are confined to a separate loopback TLS server.
		// Its marker differs from the authenticated probe, so fallback cannot pass a test.
		camouflage := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "private-camouflage-only")
		}))
		cert, err := tls.LoadX509KeyPair(filepath.Join(directory, "cert.pem"), filepath.Join(directory, "key.pem"))
		if err != nil {
			t.Fatal("private camouflage certificate unavailable")
		}
		camouflage.EnableHTTP2 = true
		camouflage.Config.ErrorLog = log.New(io.Discard, "", 0)
		camouflage.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{tls.X25519}}
		camouflage.StartTLS()
		defer camouflage.Close()
		address := netip.MustParseAddrPort(camouflage.Listener.Addr().String())
		inbound["tls"] = map[string]any{"enabled": true, "server_name": "outer.example.test", "alpn": alpn,
			"reality": map[string]any{"enabled": true, "handshake": map[string]any{"server": address.Addr().String(), "server_port": address.Port()},
				"private_key": base64.RawURLEncoding.EncodeToString(key.Bytes()), "short_id": []string{shortID}}}
	}
	if selectedTransport != "" {
		transport := map[string]any{"type": string(selectedTransport)}
		if selectedTransport == backend.GRPC {
			transport["service_name"] = "private-poc"
		} else {
			transport["path"] = "/private-transport"
		}
		if selectedTransport == backend.HTTPUpgrade {
			transport["host"] = "front.example.test"
		}
		server["inbounds"].([]any)[0].(map[string]any)["transport"] = transport
	}
	startEngine(t, ctx, binary, directory, "server", server, readyPort)
	observations := make(chan Hello, 8)
	relayAddress := ""
	var ownedRelay backend.OwnedResource
	udpObservations := make(chan struct{}, 8)
	fixedTarget := netip.MustParseAddrPort(net.JoinHostPort(serverHost, strconv.Itoa(serverPort)))
	if protocol == "hysteria2" {
		relay, err := StartUDP(ctx, UDPConfig{FakeHopLimit: options.fakeHopLimit, Target: fixedTarget, Username: "relay", Password: relaySecret, Lifetime: 15 * time.Second, Fake: []byte("invalid-loopback-quic-fake"), Observe: func(source netip.AddrPort, fake, real int) {
			if source.Addr().IsLoopback() && fake > 0 && real >= 1200 {
				udpObservations <- struct{}{}
			}
		}})
		if err != nil {
			t.Fatal(err)
		}
		defer relay.Close()
		ownedRelay = relay
		relayAddress = relay.Address()
	} else {
		relay, err := StartTCP(ctx, TCPConfig{Target: fixedTarget, ServerName: "outer.example.test", Username: "relay", Password: relaySecret, Lifetime: 15 * time.Second, Observe: func(h Hello, lengths []int) {
			if len(lengths) == 3 && lengths[0] == 1 && lengths[1] == h.HostOffset-1 {
				observations <- h
			}
		}})
		if err != nil {
			t.Fatal(err)
		}
		defer relay.Close()
		ownedRelay = relay
		relayAddress = relay.Address()
	}
	_, relayPortText, _ := net.SplitHostPort(relayAddress)
	relayPort, _ := strconv.Atoi(relayPortText)
	outbound := map[string]any{"type": protocol, "tag": "server", "server": serverHost, "server_port": serverPort, credentialField: credential, "detour": "outer-relay", "tls": map[string]any{"enabled": true, "server_name": "outer.example.test", "certificate": certificate, "alpn": alpn}}
	if failure == "bad-pin" || failure == "good-pin" {
		tlsOptions := outbound["tls"].(map[string]any)
		delete(tlsOptions, "certificate")
		tlsOptions["certificate_public_key_sha256"] = []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
	}
	if failure == "good-pin" {
		block, _ := pem.Decode([]byte(certificate))
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		outbound["tls"].(map[string]any)["certificate_public_key_sha256"] = []string{base64.StdEncoding.EncodeToString(digest[:])}
	}
	if failure == "bad-credential" {
		if protocol == "vless" {
			outbound[credentialField] = "00000000-0000-4000-a000-000000000001"
		} else {
			outbound[credentialField] = sessionSecret(t)
		}
	}
	client := map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{map[string]any{"type": "socks", "listen": "127.0.0.1", "listen_port": clientPort, "users": []any{map[string]any{"username": "probe", "password": probeSecret}}}}, "outbounds": []any{outbound, map[string]any{"type": "socks", "tag": "outer-relay", "server": "127.0.0.1", "server_port": relayPort, "version": "5", "username": "relay", "password": relaySecret}}, "route": map[string]any{"final": "server"}}
	if failure == "" {
		// Keep explicit private-CA coverage alongside the typed compiler's pin-only path.
		startEngine(t, ctx, binary, directory, "client", client, clientPort)
	} else {
		block, _ := pem.Decode([]byte(certificate))
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		pin := base64.StdEncoding.EncodeToString(digest[:])
		if failure == "bad-pin" {
			pin = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		}
		selected := backend.VLESSTLS
		if protocol == "trojan" {
			selected = backend.TrojanTLS
		} else if protocol == "hysteria2" {
			selected = backend.Hysteria2TLS
		}
		path, hostHeader, serviceName := "", "", ""
		if selectedTransport == backend.WebSocket || selectedTransport == backend.HTTPUpgrade {
			path, hostHeader = "/private-transport", "front.example.test"
		} else if selectedTransport == backend.GRPC {
			serviceName = "private-poc"
		}
		plan := backend.LoopbackPlan{Engine: backend.SingBox, Protocol: selected,
			Target: fixedTarget, Relay: netip.MustParseAddrPort(relayAddress),
			Listen: netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", clientPort)), ServerName: "outer.example.test",
			Pin: pin, Credential: outbound[credentialField].(string), RelayUser: "relay", RelayPassword: relaySecret,
			ProbeUser: "probe", ProbePassword: probeSecret, HTTPTransport: selectedTransport,
			Path: path, HostHeader: hostHeader, ServiceName: serviceName}
		if vision && failure != "bad-flow" {
			plan.Flow = "xtls-rprx-vision"
		}
		if options.variant == "fingerprint" {
			plan.Fingerprint = "chrome"
		}
		if salamander {
			plan.ObfsPassword = obfsPassword
			if failure == "bad-obfs" {
				plan.ObfsPassword = sessionSecret(t)
			}
			if failure == "missing-obfs" {
				plan.ObfsPassword = ""
			}
		}
		if reality {
			plan.Protocol, plan.Pin, plan.Fingerprint = backend.VLESSReality, "", "chrome"
			plan.RealityPublicKey, plan.RealityShortID = publicKey, shortID
			if failure == "bad-key" {
				wrong, err := ecdh.X25519().GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal("private wrong-key fixture unavailable")
				}
				plan.RealityPublicKey = base64.RawURLEncoding.EncodeToString(wrong.PublicKey().Bytes())
			}
			if failure == "bad-short-id" {
				plan.RealityShortID = ""
			}
		}
		var probeCheck *ownedHTTPSProbeCase
		if options.ownedProbe != "" {
			probeCheck = &ownedHTTPSProbeCase{spec: backend.LoopbackHTTPSProbe{Target: netip.MustParseAddrPort(target.Listener.Addr().String()), ServerName: "127.0.0.1", CertificateDER: target.Certificate().Raw, ExpectedBody: []byte("real-private-https-marker"), Timeout: 5 * time.Second}}
			if options.ownedProbe == "bad-name" {
				probeCheck.spec.ServerName = "wrong.example.test"
				probeCheck.expected = backend.Error{Code: backend.ProbeTLS}
			}
			if options.ownedProbe == "bad-marker" {
				probeCheck.spec.ExpectedBody = []byte("private-wrong-marker")
				probeCheck.expected = backend.Error{Code: backend.ProbeResponse}
			}
		}
		if options.guardianOwnerCrash {
			stopGuardian = startLoopbackOwnerCrash(t, ctx, options.guardianBinary, binary, directory, plan)
		} else if options.guardianOwned {
			stopGuardian = startSupervisedProfileClientWithProbe(t, ctx, binary, plan, alpn, ownedRelay, probeCheck, options.guardianBinary)
		} else if options.guardianBinary != "" {
			stopGuardian = startLoopbackGuardian(t, ctx, options.guardianBinary, binary, directory, plan, options.guardianTerminate)
		} else {
			startSupervisedProfileClientWithProbe(t, ctx, binary, plan, alpn, ownedRelay, probeCheck)
		}
	}
	observeTLS := func() {
		t.Helper()
		select {
		case h := <-observations:
			if h.ServerName != "outer.example.test" {
				t.Fatal("strategy applied to wrong handshake")
			}
			if reality {
				t.Logf("outer Reality Chrome ALPN: %q", h.ALPN)
				if len(h.ALPN) != 2 || h.ALPN[0] != "h2" || h.ALPN[1] != "http/1.1" {
					t.Fatal("unexpected Reality Chrome outer ALPN")
				}
			} else if selectedTransport == backend.GRPC {
				hasH2 := false
				for _, value := range h.ALPN {
					if value == "h2" {
						hasH2 = true
					}
					if value != "h2" && value != "http/1.1" {
						t.Fatal("unexpected gRPC ALPN")
					}
				}
				if !hasH2 {
					t.Fatal("gRPC outer handshake did not offer h2")
				}
				t.Logf("outer gRPC ALPN: %q", h.ALPN)
			} else if len(h.ALPN) != 1 || h.ALPN[0] != "http/1.1" {
				t.Fatal("strategy applied to wrong ALPN")
			}
		case <-time.After(time.Second):
			t.Fatal("outer handshake bypassed splitter")
		}
	}
	roots := x509.NewCertPool()
	roots.AddCert(target.Certificate())
	flows := 2
	if protocol == "hysteria2" || failure != "" {
		flows = 1
	}
	if (selectedTransport != "" || options.variant != "") && (failure == "good-pin" || failure == "good-key" || failure == "fresh-session") {
		flows = 2
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
		if strings.HasPrefix(failure, "bad-") || failure == "missing-obfs" {
			transport.CloseIdleConnections()
			if err == nil {
				response.Body.Close()
				t.Fatal("incorrect backend authentication transferred HTTPS")
			}
			if protocol == "hysteria2" {
				select {
				case <-udpObservations:
				case <-time.After(time.Second):
					t.Fatal("negative case failed before reaching outer UDP relay")
				}
			} else {
				observeTLS()
			}
			t.Log("incorrect backend authentication rejected real HTTPS transfer after outer observation")
			return
		}
		if err != nil {
			t.Fatal("real HTTPS failed through selected server and outer relay:", err)
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 128))
		response.Body.Close()
		transport.CloseIdleConnections()
		if err != nil || string(body) != "real-private-https-marker" {
			t.Fatal("missing real HTTPS response")
		}
		if protocol == "hysteria2" && i == 0 {
			select {
			case <-udpObservations:
			case <-time.After(time.Second):
				t.Fatal("new outer QUIC session bypassed fake relay")
			}
			continue
		}
		if protocol == "hysteria2" {
			continue
		}
		// gRPC can pool one TLS/HTTP2 session for multiple inner flows.
		if selectedTransport != backend.GRPC || i == 0 {
			observeTLS()
		}
	}
	_, udpSocket := associate(t, fmt.Sprintf("127.0.0.1:%d", clientPort), "probe", probeSecret)
	if _, err := udpSocket.Write(encodeUDP(udpAddress, []byte("actual-private-udp-marker"))); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 2048)
	n, err := udpSocket.Read(buffer)
	if err != nil {
		t.Fatal("real UDP failed through selected server")
	}
	payload, ok := decodeUDP(buffer[:n], udpAddress)
	if !ok || string(payload) != "actual-private-udp-marker" {
		t.Fatal("missing real UDP response")
	}
	if protocol != "hysteria2" && selectedTransport != backend.GRPC {
		observeTLS()
	}
	if stopGuardian != nil {
		stopGuardian()
	}
	if protocol == "hysteria2" {
		t.Log("fresh Hysteria2 session carried real HTTPS through outer UDP fake relay with verified TLS and h3; ordering/tuple independently tested, ISP effect not established")
	} else {
		t.Logf("%d fresh HTTPS transfers and outer SNI/ALPN split writes verified; packet boundaries and ISP effectiveness are not established", flows)
	}
}

func sessionSecret(t *testing.T) string {
	t.Helper()
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		t.Fatal("cannot generate test session secret")
	}
	return hex.EncodeToString(data)
}

// Keep raw diagnostics private and bounded; expose only known stage categories.
type boundedEngineLog struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (w *boundedEngineLog) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := len(p)
	remaining := 32768 - w.data.Len()
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = w.data.Write(p)
	}
	return n, nil
}
func (w *boundedEngineLog) categories() map[string]int {
	w.mu.Lock()
	defer w.mu.Unlock()
	value := w.data.String()
	result := map[string]int{}
	for _, term := range []string{"taking detour [direct]", "taking detour [block]", "taking default detour [block]", "peer cert is unrecognized", "invalid user", "proxy/freedom: connection opened", "connection opened to", "blocked target:", "redirecting request", "accepted", "failed to", "connection ends", "EOF"} {
		if count := strings.Count(value, term); count > 0 {
			result[term] = count
		}
	}
	return result
}
