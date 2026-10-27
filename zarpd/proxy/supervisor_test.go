package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The re-executed test binary acts only as a controlled loopback child. No real
// backend, installed daemon, TUN, route, account, or system DNS is used here.
func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "private-owner-probe-api" {
		ownerProbeAPIFixture()
		os.Exit(0)
	}
	if len(os.Args) == 2 && os.Args[1] == "private-typed-guardian-owner" {
		typedGuardianOwnerFixture()
		os.Exit(0)
	}
	if len(os.Args) == 2 && os.Args[1] == "private-descendant" {
		descendantFixture()
		os.Exit(0)
	}
	if len(os.Args) == 2 && os.Args[1] == "private-descendant-new-group" {
		descendantFixture()
		os.Exit(0)
	}
	if len(os.Args) == 2 && os.Args[1] == "private-guardian-parent" {
		guardianParentFixture()
		os.Exit(0)
	}
	if len(os.Args) == 2 && os.Args[1] == "private-guardian-worker" {
		guardianWorkerFixture(false)
		os.Exit(0)
	}
	if filepath.Base(os.Args[0]) == "engine" && len(os.Args) == 2 && (os.Args[1] == "--owned-session" || os.Args[1] == "--release-session") {
		guardianWorkerFixture(true)
		os.Exit(0)
	}
	if filepath.Base(os.Args[0]) == "engine" && len(os.Args) == 2 && os.Args[1] == "--recover-session" {
		if RunLoopbackRecovery(os.NewFile(3, "fixture-recovery-control"), os.NewFile(4, "fixture-recovery-report"),
			os.NewFile(5, "fixture-recovery-root"), os.NewFile(6, "fixture-recovery-ack")) != nil {
			os.Exit(75)
		}
		os.Exit(0)
	}
	if filepath.Base(os.Args[0]) == "engine" && len(os.Args) > 1 &&
		(os.Args[1] == "version" || os.Args[1] == "check" || os.Args[1] == "run") {
		fakeEngine()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func fakeEngine() {
	if os.Args[1] == "version" {
		fmt.Print("sing-box version 1.13.14\n")
		return
	}
	var config struct {
		Inbounds []struct {
			Port  int `json:"listen_port"`
			Users []struct{ Username, Password string }
		}
		Outbounds []struct{ Password string }
	}
	data, err := os.ReadFile(os.Args[len(os.Args)-1])
	if err != nil || json.Unmarshal(data, &config) != nil || len(config.Inbounds) != 1 || len(config.Outbounds) != 2 {
		os.Exit(23)
	}
	mode := config.Outbounds[0].Password
	if os.Args[1] == "check" {
		if mode == "check-fail" {
			fmt.Print("private-secret-invalid-config")
			os.Exit(23)
		}
		if mode == "check-hang" {
			signal.Ignore(unix.SIGTERM)
			for {
				time.Sleep(time.Hour)
			}
		}
		return
	}
	if mode == "exit" {
		os.Exit(27)
	}
	if strings.HasPrefix(mode, "spawn-descendant") {
		child := exec.Command(os.Args[0], "private-descendant")
		if mode == "spawn-descendant-new-group" {
			child.Args[1] = "private-descendant-new-group"
			child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		}
		child.Env = os.Environ() // The fake engine already received the finite environment.
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if child.Start() != nil {
			os.Exit(30)
		}
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat("descendant.json"); err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if mode == "spawn-descendant-exit" {
			return
		}
		signal.Ignore(unix.SIGTERM)
	}
	if mode == "ignore-term" || mode == "no-listener" {
		signal.Ignore(unix.SIGTERM)
	}
	if mode == "no-listener" || mode == "spawn-descendant-no-listener" {
		for {
			time.Sleep(time.Hour)
		}
	}
	if os.Getenv("XRAY_LOCATION_CONFDIR") != "" || os.Getenv("xray.location.confdir") != "" || os.Getenv("DYLD_INSERT_LIBRARIES") != "" {
		os.Exit(28)
	}
	fmt.Print(strings.Repeat("private-secret-runtime-output", 3000))
	listener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", config.Inbounds[0].Port))
	if err != nil {
		os.Exit(29)
	}
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		func() {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			var greeting [3]byte
			if _, err := io.ReadFull(conn, greeting[:]); err != nil || greeting != [3]byte{5, 1, 2} {
				return
			}
			_, _ = conn.Write([]byte{5, 2})
			var header [2]byte
			if _, err := io.ReadFull(conn, header[:]); err != nil {
				return
			}
			user := make([]byte, int(header[1]))
			if _, err := io.ReadFull(conn, user); err != nil {
				return
			}
			var size [1]byte
			if _, err := io.ReadFull(conn, size[:]); err != nil {
				return
			}
			password := make([]byte, int(size[0]))
			if _, err := io.ReadFull(conn, password); err != nil {
				return
			}
			accepted := mode != "bad-auth" && string(user) == config.Inbounds[0].Users[0].Username && string(password) == config.Inbounds[0].Users[0].Password
			code := byte(1)
			if accepted {
				code = 0
			}
			_, _ = conn.Write([]byte{1, code})
		}()
	}
}

func fakeSupervisor(t *testing.T) *Supervisor {
	t.Helper()
	root := t.TempDir()
	t.Setenv("TMPDIR", root)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "test-engine")
	if err := os.WriteFile(path, data, 0700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	supervisor, err := NewSupervisor(root)
	if err != nil {
		t.Fatal(err)
	}
	supervisor.specs = map[Engine]engineSpec{
		SingBox: {"test-engine", "1.13.14", hex.EncodeToString(digest[:]), "sing-box version 1.13.14\n"},
	}
	return supervisor
}

func testPlan(t *testing.T, credential string) LoopbackPlan {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := listener.Addr().(*net.TCPAddr).AddrPort()
	_ = listener.Close()
	return LoopbackPlan{Engine: SingBox, Protocol: TrojanTLS, Target: netip.MustParseAddrPort("127.0.0.1:443"),
		Relay: netip.MustParseAddrPort("127.0.0.1:1080"), Listen: listen, ServerName: "outer.example.test",
		Pin: base64.StdEncoding.EncodeToString(make([]byte, 32)), Credential: credential,
		RelayUser: "relay", RelayPassword: "private-relay-secret", ProbeUser: "probe", ProbePassword: "private-probe-secret"}
}

func assertPrivateClean(t *testing.T, supervisor *Supervisor) {
	t.Helper()
	entries, err := os.ReadDir(supervisor.root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "zarp-engine-") {
			t.Fatal("owned private configuration remains after cleanup")
		}
	}
}

func TestSupervisorAuthenticatedReadinessCancellationAndPrivacy(t *testing.T) {
	s := fakeSupervisor(t)
	t.Setenv("XRAY_LOCATION_CONFDIR", "private-untrusted-env")
	t.Setenv("xray.location.confdir", "private-untrusted-env")
	ctx, cancel := context.WithCancel(context.Background())
	session, err := s.StartLoopback(ctx, testPlan(t, "ignore-term"), DefaultLimits())
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = session.Close() })
	status := session.Status()
	if status.State != Ready || status.Version != "1.13.14" {
		t.Fatal("authenticated listener was not ready")
	}
	for path, mode := range map[string]os.FileMode{session.dir: 0700, filepath.Join(session.dir, "config.json"): 0600, filepath.Join(session.dir, "engine"): 0500} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatal("private resource permissions incorrect")
		}
	}
	count, capped := session.child.output.counts()
	if count != diagnosticLimit || !capped || session.child.output.text() != "" {
		t.Fatal("runtime output was unbounded or retained")
	}
	started := time.Now()
	cancel()
	if err := session.Close(); err != nil || time.Since(started) > 3*time.Second {
		t.Fatal("owned TERM-ignoring process cleanup failed")
	}
	if session.Status().State != Stopped || !session.Status().CleanupOK {
		t.Fatal("cancelled runtime has incorrect terminal state")
	}
	assertPrivateClean(t, s)
	if err := session.Close(); err != nil {
		t.Fatal("close was not idempotent")
	}
	raw, _ := json.Marshal(session.Status())
	if strings.Contains(string(raw), "private") {
		t.Fatal("status disclosed a secret")
	}
}

func TestSupervisorLeaseAndEarlyExit(t *testing.T) {
	for _, mode := range []string{"normal", "exit"} {
		t.Run(mode, func(t *testing.T) {
			s := fakeSupervisor(t)
			// Race-instrumented helper processes wait one second before clean exit.
			limits := Limits{StartupTimeout: 4 * time.Second, Lifetime: 5 * time.Second, StopGrace: 20 * time.Millisecond}
			session, err := s.StartLoopback(context.Background(), testPlan(t, mode), limits)
			if mode == "exit" {
				if err == nil {
					_ = session.Close()
					t.Fatal("failed child was reported ready")
				}
				if err != (Error{Startup}) {
					t.Fatalf("early child failure reported %v instead of startup failure", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				select {
				case <-session.Done():
				case <-time.After(6 * time.Second):
					_ = session.Close()
					t.Fatal("lease did not stop child")
				}
				if session.Status().State != Expired || !session.Status().CleanupOK {
					t.Fatal("lease did not report bounded cleanup")
				}
			}
			assertPrivateClean(t, s)
		})
	}
}

func TestSupervisorIncompleteStartupTeardown(t *testing.T) {
	for _, mode := range []string{"check-fail", "check-hang", "bad-auth", "no-listener"} {
		t.Run(mode, func(t *testing.T) {
			s := fakeSupervisor(t)
			limits := Limits{StartupTimeout: 3500 * time.Millisecond, Lifetime: 5 * time.Second, StopGrace: 20 * time.Millisecond}
			started := time.Now()
			session, err := s.StartLoopback(context.Background(), testPlan(t, mode), limits)
			if err == nil {
				_ = session.Close()
				t.Fatal("incomplete runtime reported ready")
			}
			if time.Since(started) > 4*time.Second || strings.Contains(err.Error(), "private") {
				t.Fatal("startup deadline or redaction failed")
			}
			code := Readiness
			if mode == "check-fail" {
				code = Configuration
			} else if mode == "check-hang" {
				code = Cancelled
			}
			if err != (Error{code}) {
				t.Fatalf("expected failure at %s, received %v", code, err)
			}
			assertPrivateClean(t, s)
		})
	}
}

func TestSupervisorIntegrityVersionAndResourceRefusal(t *testing.T) {
	for _, kind := range []string{"tampered", "symlink", "fifo", "writable", "version"} {
		t.Run(kind, func(t *testing.T) {
			s := fakeSupervisor(t)
			path := filepath.Join(s.root, "test-engine")
			code := BinaryUnavailable
			switch kind {
			case "tampered":
				if err := os.WriteFile(path, []byte("tampered executable"), 0700); err != nil {
					t.Fatal(err)
				}
				code = BinaryIntegrity
			case "symlink":
				if err := os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".original", path); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				_ = os.Remove(path)
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "writable":
				if err := os.Chmod(path, 0770); err != nil {
					t.Fatal(err)
				}
			case "version":
				spec := s.specs[SingBox]
				spec.versionPrefix = "wrong-version"
				s.specs[SingBox] = spec
				code = VersionMismatch
			}
			_, err := s.StartLoopback(context.Background(), testPlan(t, "normal"), DefaultLimits())
			if err != (Error{code}) {
				t.Fatalf("expected %s, received %v", code, err)
			}
			assertPrivateClean(t, s)
		})
	}
}

func TestPlanRestrictsDestinationsParametersAndPinSemantics(t *testing.T) {
	valid := testPlan(t, "private-server-password")
	for _, mutate := range []func(*LoopbackPlan){
		func(p *LoopbackPlan) { p.Target = netip.MustParseAddrPort("1.1.1.1:443") },
		func(p *LoopbackPlan) { p.Relay = netip.MustParseAddrPort("[::1]:1080") },
		func(p *LoopbackPlan) { p.Listen = p.Relay },
		func(p *LoopbackPlan) { p.Protocol = XHTTPH3 },
		func(p *LoopbackPlan) { p.Engine = Engine("/bin/sh") },
		func(p *LoopbackPlan) { p.Pin = "private-invalid-pin" },
		func(p *LoopbackPlan) { p.ProbePassword = "private\nsecret" },
		func(p *LoopbackPlan) { p.Credential = string([]byte{0xff}) },
		func(p *LoopbackPlan) { p.Pin += "\n" },
		func(p *LoopbackPlan) { p.ServerName = "private-invalid/name" },
		func(p *LoopbackPlan) { p.Protocol = VLESSTLS },
	} {
		invalid := valid
		mutate(&invalid)
		if _, err := invalid.compile(); err != (Error{InvalidPlan}) {
			t.Fatal("unsafe plan was accepted")
		}
	}
	if strings.Contains(fmt.Sprintf("%v %#v", valid, valid), "private") {
		t.Fatal("plan display leaked credentials")
	}
	for _, engine := range []Engine{SingBox, Xray} {
		for _, protocol := range []Protocol{VLESSTLS, TrojanTLS, Hysteria2TLS, XHTTPH2, XHTTPH3} {
			p := valid
			p.Engine, p.Protocol = engine, protocol
			if protocol != TrojanTLS && protocol != Hysteria2TLS {
				p.Credential = "00000000-0000-4000-a000-000000000001"
			}
			if engine == Xray {
				p.Pin = strings.Repeat("0", 64)
			}
			_, err := p.compile()
			expected := engine == SingBox && (protocol == VLESSTLS || protocol == TrojanTLS || protocol == Hysteria2TLS) ||
				engine == Xray && (protocol == VLESSTLS || protocol == XHTTPH2 || protocol == XHTTPH3)
			if (err == nil) != expected {
				t.Fatal("unsupported combination silently accepted or supported plan refused")
			}
		}
	}
}

func TestDiscardedDiagnosticsBoundedUnderConcurrency(t *testing.T) {
	w := &boundedOutput{}
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() { defer workers.Done(); _, _ = w.Write([]byte(strings.Repeat("private-secret", 10000))) }()
	}
	workers.Wait()
	count, capped := w.counts()
	if count != diagnosticLimit || !capped || w.text() != "" {
		t.Fatal("diagnostics retained secret bytes or exceeded bound")
	}
}

func TestVerifiedSnapshotIsIndependentOfInventoryReplacement(t *testing.T) {
	s := fakeSupervisor(t)
	dir := t.TempDir()
	path, err := s.snapshot(context.Background(), s.specs[SingBox], dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.root, "test-engine"), []byte("replaced source"), 0700); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != s.specs[SingBox].digest {
		t.Fatal("verified executable changed after inventory replacement")
	}
}

func TestSupervisorCancelledBeforeStartup(t *testing.T) {
	s := fakeSupervisor(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.StartLoopback(ctx, testPlan(t, "normal"), DefaultLimits()); err != (Error{Cancelled}) {
		t.Fatal("pre-cancelled startup did not refuse execution")
	}
	assertPrivateClean(t, s)
	if _, err := s.StartLoopback(context.Background(), testPlan(t, "normal"), Limits{}); err != (Error{InvalidLimits}) {
		t.Fatal("invalid lifecycle bounds accepted")
	}
	assertPrivateClean(t, s)
}

func TestSupervisorCancellationDuringReadinessIsNotFailure(t *testing.T) {
	s := fakeSupervisor(t)
	plan := testPlan(t, "bad-auth")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		session, err := s.StartLoopback(ctx, plan, DefaultLimits())
		if session != nil {
			_ = session.Close()
		}
		result <- err
	}()
	deadline := time.Now().Add(4 * time.Second)
	listening := false
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", plan.Listen.String(), 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			listening = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-result:
		if !listening || err != (Error{Cancelled}) {
			t.Fatalf("cancellation during authentication reported %v, listener seen: %v", err, listening)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled startup did not clean up")
	}
	assertPrivateClean(t, s)
}

func TestHTTPTransportOptionsRejectInapplicableFields(t *testing.T) {
	base := testPlan(t, "test-only-password")
	for _, change := range []func(*LoopbackPlan){
		func(p *LoopbackPlan) { p.Path = "/ignored" },
		func(p *LoopbackPlan) { p.HTTPTransport = HTTPTransport("private-unknown") },
		func(p *LoopbackPlan) { p.HTTPTransport = WebSocket; p.ServiceName = "ignored" },
		func(p *LoopbackPlan) { p.HTTPTransport = WebSocket; p.Path = "relative" },
		func(p *LoopbackPlan) { p.HTTPTransport = WebSocket; p.HostHeader = "invalid/host" },
		func(p *LoopbackPlan) { p.HTTPTransport = GRPC; p.HostHeader = "ignored.example" },
		func(p *LoopbackPlan) { p.HTTPTransport = GRPC; p.Path = "/ignored" },
		func(p *LoopbackPlan) { p.HTTPTransport = GRPC; p.ServiceName = "invalid\nservice" },
		func(p *LoopbackPlan) { p.HTTPTransport = HTTPUpgrade; p.Protocol = Hysteria2TLS },
		func(p *LoopbackPlan) { p.HTTPTransport = WebSocket; p.Engine = Xray },
	} {
		p := base
		change(&p)
		if _, err := p.compile(); err != (Error{InvalidPlan}) {
			t.Fatal("inapplicable HTTP transport option accepted")
		}
	}
	for _, transport := range []HTTPTransport{WebSocket, GRPC, HTTPUpgrade} {
		p := base
		p.HTTPTransport = transport
		if _, err := p.compile(); err != nil {
			t.Fatal("supported transport with defaults refused")
		}
	}
}
