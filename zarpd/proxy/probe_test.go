package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type probeRuntime struct {
	ctx      context.Context
	cancel   context.CancelFunc
	deadline time.Time
}

func (s *probeRuntime) Done() <-chan struct{} { return s.ctx.Done() }
func (s *probeRuntime) Status() Status {
	return Status{Engine: SingBox, Version: "1.13.14", State: Ready, CleanupOK: s.ctx.Err() != nil, LeaseExpiresAt: s.deadline}
}
func (s *probeRuntime) Close() error { s.cancel(); return nil }
func (s *probeRuntime) RenewLease() error {
	if s.ctx.Err() != nil {
		return Error{Inactive}
	}
	return nil
}
func (s *probeRuntime) readyStatus() (Status, bool) { return s.Status(), s.ctx.Err() == nil }

type probeBackend struct{}

func (probeBackend) versionFor(Engine) (string, bool) { return "1.13.14", true }
func (probeBackend) StartLoopbackChain(ctx context.Context, p LoopbackPlan, l Limits, r OwnedResource) (*Chain, error) {
	return startLoopbackChain(ctx, p, l, r, func(ctx context.Context, _ LoopbackPlan, _ Limits) (runtimeSession, error) {
		ctx, cancel := context.WithTimeout(ctx, l.Lifetime)
		return &probeRuntime{ctx: ctx, cancel: cancel, deadline: time.Now().Add(l.Lifetime)}, nil
	})
}

type probeSOCKSFixture struct {
	listener    net.Listener
	target      netip.AddrPort
	mode        string
	accepted    atomic.Int32
	closed      atomic.Int32
	seen        chan struct{}
	done        chan struct{}
	workers     sync.WaitGroup
	mu          sync.Mutex
	connections map[net.Conn]bool
}

func startProbeSOCKSFixture(t *testing.T, target netip.AddrPort, mode string) *probeSOCKSFixture {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &probeSOCKSFixture{listener: listener, target: target, mode: mode, seen: make(chan struct{}, 8), done: make(chan struct{}), connections: map[net.Conn]bool{}}
	go func() {
		defer close(f.done)
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			f.accepted.Add(1)
			f.mu.Lock()
			f.connections[c] = true
			f.mu.Unlock()
			f.workers.Add(1)
			go func() {
				defer f.workers.Done()
				defer func() { _ = c.Close(); f.mu.Lock(); delete(f.connections, c); f.mu.Unlock() }()
				f.serve(c)
			}()
		}
	}()
	t.Cleanup(func() { _ = f.CloseBounded(context.Background()) })
	return f
}
func (f *probeSOCKSFixture) CloseBounded(context.Context) error {
	if !f.closed.CompareAndSwap(0, 1) {
		return nil
	}
	_ = f.listener.Close()
	<-f.done
	f.mu.Lock()
	for c := range f.connections {
		_ = c.Close()
	}
	f.mu.Unlock()
	f.workers.Wait()
	return nil
}
func (f *probeSOCKSFixture) serve(c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	var hello [3]byte
	if _, err := io.ReadFull(c, hello[:]); err != nil || hello != [3]byte{5, 1, 2} {
		return
	}
	f.seen <- struct{}{}
	if f.mode == "stall" {
		_, _ = io.Copy(io.Discard, c)
		return
	}
	if f.mode == "no-auth" {
		_, _ = c.Write([]byte{5, 0})
		return
	}
	_, _ = c.Write([]byte{5, 2})
	var header [2]byte
	if _, err := io.ReadFull(c, header[:]); err != nil || header[0] != 1 {
		return
	}
	user := make([]byte, int(header[1]))
	if _, err := io.ReadFull(c, user); err != nil {
		return
	}
	if _, err := io.ReadFull(c, header[:1]); err != nil {
		return
	}
	password := make([]byte, int(header[0]))
	if _, err := io.ReadFull(c, password); err != nil {
		return
	}
	if string(user) != "probe" || string(password) != "private-probe-secret" || f.mode == "bad-auth" {
		_, _ = c.Write([]byte{1, 1})
		return
	}
	_, _ = c.Write([]byte{1, 0})
	var connect [4]byte
	if _, err := io.ReadFull(c, connect[:]); err != nil || connect[0] != 5 || connect[1] != 1 || connect[2] != 0 {
		return
	}
	width := 4
	if connect[3] == 4 {
		width = 16
	} else if connect[3] != 1 {
		return
	}
	address := make([]byte, width+2)
	if _, err := io.ReadFull(c, address); err != nil {
		return
	}
	ip, ok := netip.AddrFromSlice(address[:width])
	if !ok || netip.AddrPortFrom(ip, binary.BigEndian.Uint16(address[width:])) != f.target {
		return
	}
	upstream, err := net.DialTimeout("tcp", f.target.String(), time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()
	reply := []byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}
	switch f.mode {
	case "reply-foreign":
		reply[4] = 198
	case "reply-domain":
		reply[3] = 3
	case "reply-code":
		reply[1] = 1
	case "reply-reserved":
		reply[2] = 1
	}
	_, _ = c.Write(reply)
	copied := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, c); copied <- struct{}{} }()
	go func() { _, _ = io.Copy(c, upstream); copied <- struct{}{} }()
	<-copied
	_ = upstream.Close()
	_ = c.Close()
	<-copied
}

func probeFixture(t *testing.T, mode string, handler http.HandlerFunc) (*RuntimeOwner, RuntimeSnapshot, LoopbackHTTPSProbe, *probeSOCKSFixture) {
	t.Helper()
	if handler == nil {
		handler = func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "private-probe-marker") }
	}
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	if mode == "ipv6-target" {
		_ = server.Listener.Close()
		listener, err := net.Listen("tcp6", "[::1]:0")
		if err != nil {
			t.Fatal(err)
		}
		server.Listener = listener
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	target := netip.MustParseAddrPort(server.Listener.Addr().String())
	f := startProbeSOCKSFixture(t, target, mode)
	owner := NewRuntimeOwner(context.Background(), probeBackend{})
	t.Cleanup(func() { _ = owner.Close() })
	profile, access := ownerInputs(t, "private-server-secret")
	access.Listen = netip.MustParseAddrPort(f.listener.Addr().String())
	started, err := owner.StartLoopback(context.Background(), profile, access, strings.Repeat("a", 64), ownerLimits(), f)
	if err != nil {
		t.Fatal(err)
	}
	spec := LoopbackHTTPSProbe{Target: target, ServerName: target.Addr().String(), CertificateDER: server.Certificate().Raw, ExpectedBody: []byte("private-probe-marker"), Timeout: time.Second}
	return owner, started, spec, f
}

func TestOwnedHTTPSProbeTransfersTwoFreshRequestsWithoutRenewingLease(t *testing.T) {
	var mu sync.Mutex
	peers := map[string]bool{}
	o, start, spec, f := probeFixture(t, "", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.NegotiatedProtocol != "http/1.1" || r.Method != "GET" || r.URL.Path != "/" || r.Header.Get("Accept-Encoding") != "identity" || r.Header.Get("Cookie") != "" {
			t.Error("invalid private HTTPS probe request")
		}
		mu.Lock()
		peers[r.RemoteAddr] = true
		mu.Unlock()
		_, _ = io.WriteString(w, "private-probe-marker")
	})
	result, err := o.ProbeLoopbackHTTPS(context.Background(), start.RunID, spec)
	if err != nil || result.RunID != start.RunID || result.ServerID != start.ServerID || result.StrategyFingerprint != start.StrategyFingerprint || result.FirstResponseMillis[0] < 1 || result.FirstResponseMillis[1] < 1 {
		t.Fatal("real private HTTPS probe failed", err)
	}
	mu.Lock()
	fresh := len(peers)
	mu.Unlock()
	if f.accepted.Load() != 2 || fresh != 2 {
		t.Fatal("confirmation reused an inner connection")
	}
	current, err := o.Adopt()
	if err != nil || !current.Backend.LeaseExpiresAt.Equal(start.Backend.LeaseExpiresAt) {
		t.Fatal("probe mutated lease/adoption")
	}
	data, _ := json.Marshal(result)
	for _, secret := range []string{"private-probe-secret", spec.ServerName, string(spec.ExpectedBody), "private-server-secret"} {
		if strings.Contains(string(data), secret) {
			t.Fatal("probe result exposed private data")
		}
	}
	if err := o.Stop(start.RunID); err != nil || f.closed.Load() != 1 {
		t.Fatal("probe chain cleanup failed")
	}
	if o.run.probe != (probeAccess{}) {
		t.Fatal("terminal run retained probe credentials")
	}
}

func unrelatedProbeCertificate(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	data, err := x509.CreateCertificate(rand.Reader, c, c, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestOwnedHTTPSProbeRejectsTLSAuthenticationResponsesAndPartialConfirmation(t *testing.T) {
	for _, mode := range []string{"no-auth", "bad-auth", "reply-foreign", "reply-domain", "reply-code", "reply-reserved", "wrong-name", "wrong-cert", "redirect", "body", "overflow", "headers", "encoding", "second"} {
		t.Run(mode, func(t *testing.T) {
			var requests atomic.Int32
			o, start, spec, f := probeFixture(t, mode, func(w http.ResponseWriter, r *http.Request) {
				n := requests.Add(1)
				switch mode {
				case "redirect":
					w.Header().Set("Location", "https://example.invalid/private-token")
					w.WriteHeader(302)
				case "body":
					_, _ = io.WriteString(w, "private-wrong-secret-marker")
				case "overflow":
					_, _ = io.WriteString(w, strings.Repeat("x", 4097))
				case "headers":
					w.Header().Set("X-Private", strings.Repeat("x", 17000))
					_, _ = io.WriteString(w, "private-probe-marker")
				case "encoding":
					w.Header().Set("Content-Encoding", "gzip")
					_, _ = io.WriteString(w, "private-probe-marker")
				case "second":
					if n == 2 {
						w.WriteHeader(503)
					} else {
						_, _ = io.WriteString(w, "private-probe-marker")
					}
				default:
					_, _ = io.WriteString(w, "private-probe-marker")
				}
			})
			if mode == "wrong-name" {
				spec.ServerName = "wrong.example.test"
			}
			if mode == "wrong-cert" {
				spec.CertificateDER = unrelatedProbeCertificate(t)
			}
			result, err := o.ProbeLoopbackHTTPS(context.Background(), start.RunID, spec)
			expected := Error{ProbeResponse}
			if mode == "wrong-name" || mode == "wrong-cert" {
				expected = Error{ProbeTLS}
			}
			if mode == "no-auth" || mode == "bad-auth" || strings.HasPrefix(mode, "reply-") {
				expected = Error{ProbeTransport}
			}
			if err != expected || result != (HTTPSProbeResult{}) {
				t.Fatal("invalid/partial response certified health", err)
			}
			if err := o.Stop(start.RunID); err != nil || f.closed.Load() != 1 {
				t.Fatal("failed probe retained owned chain")
			}
		})
	}
}

func TestOwnedHTTPSProbeBoundsAndRedactsBeforeNetworkAccess(t *testing.T) {
	o, start, spec, f := probeFixture(t, "", nil)
	for _, mutate := range []func(*LoopbackHTTPSProbe){
		func(s *LoopbackHTTPSProbe) { s.Target = netip.MustParseAddrPort("192.0.2.1:443") },
		func(s *LoopbackHTTPSProbe) { s.ServerName = "private\nsecret" }, func(s *LoopbackHTTPSProbe) { s.CertificateDER = []byte("private-secret") },
		func(s *LoopbackHTTPSProbe) { s.CertificateDER = make([]byte, 8193) }, func(s *LoopbackHTTPSProbe) { s.ExpectedBody = nil },
		func(s *LoopbackHTTPSProbe) { s.ExpectedBody = make([]byte, 4097) }, func(s *LoopbackHTTPSProbe) { s.Timeout = 0 }, func(s *LoopbackHTTPSProbe) { s.Timeout = 16 * time.Second },
	} {
		changed := spec
		mutate(&changed)
		if _, err := o.ProbeLoopbackHTTPS(context.Background(), start.RunID, changed); err != (Error{InvalidProbe}) {
			t.Fatal("invalid probe reached dial")
		}
	}
	if _, err := o.ProbeLoopbackHTTPS(context.Background(), "private-stale-generation", spec); err != (Error{Inactive}) {
		t.Fatal("stale run reached dial")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := o.ProbeLoopbackHTTPS(ctx, start.RunID, spec); err != (Error{Cancelled}) {
		t.Fatal("cancelled request reached dial")
	}
	if f.accepted.Load() != 0 {
		t.Fatal("refused probe touched listener")
	}
	if strings.Contains(spec.String(), "secret") || strings.Contains(spec.GoString(), "secret") {
		t.Fatal("probe formatting exposed data")
	}
}

func TestOwnedHTTPSProbeCancellationBusyAndStopJoin(t *testing.T) {
	for _, action := range []string{"cancel", "deadline", "stop", "close"} {
		t.Run(action, func(t *testing.T) {
			o, start, spec, f := probeFixture(t, "stall", nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if action == "deadline" {
				spec.Timeout = 150 * time.Millisecond
			}
			result := make(chan error, 1)
			go func() { _, err := o.ProbeLoopbackHTTPS(ctx, start.RunID, spec); result <- err }()
			select {
			case <-f.seen:
			case <-time.After(time.Second):
				t.Fatal("probe did not reach private handshake")
			}
			if _, err := o.ProbeLoopbackHTTPS(context.Background(), start.RunID, spec); err != (Error{Busy}) {
				t.Fatal("concurrent probe was admitted")
			}
			expected := Error{Cancelled}
			switch action {
			case "cancel":
				cancel()
			case "deadline":
				expected = Error{ProbeTimeout}
			case "stop":
				expected = Error{Inactive}
				if err := o.Stop(start.RunID); err != nil {
					t.Fatal(err)
				}
			case "close":
				expected = Error{Inactive}
				if err := o.Close(); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err := <-result:
				if err != expected {
					t.Fatal("probe cancellation result wrong", err)
				}
			case <-time.After(time.Second):
				t.Fatal("probe did not join on cancellation")
			}
			o.mu.Lock()
			busy := o.run.probeBusy
			o.mu.Unlock()
			if busy {
				t.Fatal("probe admission slot retained")
			}
			if action == "stop" || action == "close" {
				if f.closed.Load() != 1 || o.run.probe != (probeAccess{}) {
					t.Fatal("cleanup did not join and erase probe access")
				}
			}
		})
	}
}

func TestOwnedHTTPSProbeStaleGenerationCannotMeasureReplacement(t *testing.T) {
	o, first, spec, _ := probeFixture(t, "", nil)
	if err := o.Stop(first.RunID); err != nil {
		t.Fatal(err)
	}
	f := startProbeSOCKSFixture(t, spec.Target, "")
	profile, access := ownerInputs(t, "private-server-secret")
	access.Listen = netip.MustParseAddrPort(f.listener.Addr().String())
	second, err := o.StartLoopback(context.Background(), profile, access, strings.Repeat("a", 64), ownerLimits(), f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.ProbeLoopbackHTTPS(context.Background(), first.RunID, spec); err != (Error{Inactive}) || f.accepted.Load() != 0 {
		t.Fatal("stale generation contacted replacement")
	}
	result, err := o.ProbeLoopbackHTTPS(context.Background(), second.RunID, spec)
	if err != nil || result.RunID != second.RunID || f.accepted.Load() != 2 {
		t.Fatal("replacement could not verify itself", err)
	}
}

func TestOwnedHTTPSProbeAdmissionAndStopSerializeJoining(t *testing.T) {
	for i := 0; i < 12; i++ {
		o, start, spec, f := probeFixture(t, "stall", nil)
		goNow := make(chan struct{})
		result := make(chan error, 1)
		stopped := make(chan error, 1)
		go func() {
			<-goNow
			_, err := o.ProbeLoopbackHTTPS(context.Background(), start.RunID, spec)
			result <- err
		}()
		go func() { <-goNow; stopped <- o.Stop(start.RunID) }()
		close(goNow)
		select {
		case err := <-stopped:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("stop did not join admitted probe")
		}
		select {
		case err := <-result:
			if err != (Error{Inactive}) {
				t.Fatal("stopped generation credited probe", err)
			}
		case <-time.After(time.Second):
			t.Fatal("probe survived stop")
		}
		if f.closed.Load() != 1 || o.run.probeBusy || o.run.probe != (probeAccess{}) {
			t.Fatal("probe/resource survived terminal owner state")
		}
	}
}

func TestOwnedHTTPSProbeSupportsNumericIPv6InnerTarget(t *testing.T) {
	o, start, spec, f := probeFixture(t, "ipv6-target", nil)
	if !spec.Target.Addr().Is6() {
		t.Fatal("fixture did not bind IPv6")
	}
	result, err := o.ProbeLoopbackHTTPS(context.Background(), start.RunID, spec)
	if err != nil || result.FirstResponseMillis[0] < 1 || f.accepted.Load() != 2 {
		t.Fatal("IPv6 inner HTTPS confirmation failed", err)
	}
}

func TestOwnedHTTPSProbeCancelDuringResponseBodyJoinsConnection(t *testing.T) {
	bodyStarted := make(chan struct{})
	bodyStopped := make(chan struct{})
	o, start, spec, _ := probeFixture(t, "", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "20")
		_, _ = io.WriteString(w, "p")
		w.(http.Flusher).Flush()
		close(bodyStarted)
		<-r.Context().Done()
		close(bodyStopped)
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := o.ProbeLoopbackHTTPS(ctx, start.RunID, spec); result <- err }()
	select {
	case <-bodyStarted:
	case <-time.After(time.Second):
		t.Fatal("probe did not read real response headers")
	}
	cancel()
	select {
	case err := <-result:
		if err != (Error{Cancelled}) {
			t.Fatal("body cancellation did not remain cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("body read remained blocked")
	}
	select {
	case <-bodyStopped:
	case <-time.After(time.Second):
		t.Fatal("private upstream connection remained open")
	}
}
