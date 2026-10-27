package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"
)

const (
	InvalidProbe   Code = "invalid_probe"
	ProbeTransport Code = "probe_transport_failed"
	ProbeTLS       Code = "probe_tls_failed"
	ProbeResponse  Code = "probe_response_failed"
	ProbeTimeout   Code = "probe_timeout"
)

// LoopbackHTTPSProbe is trusted test construction data, never an IPC request or
// imported profile. Its target is numeric loopback, its dedicated certificate
// must validate normally, and its exact response marker is bounded. No public
// URL, CA installation, WARP trace, system resolver or frontend is used.
type LoopbackHTTPSProbe struct {
	Target         netip.AddrPort
	ServerName     string
	CertificateDER []byte
	ExpectedBody   []byte
	Timeout        time.Duration // Shared by both fresh requests, at most 15 seconds.
}

func (LoopbackHTTPSProbe) String() string   { return "LoopbackHTTPSProbe(redacted)" }
func (LoopbackHTTPSProbe) GoString() string { return "LoopbackHTTPSProbe(redacted)" }

// HTTPSProbeResult contains no target, credentials, raw errors, body or cert.
// Timings cover SOCKS/TLS through the first real response byte, and are credited
// only after both complete responses validate. Fresh inner connections do not
// establish independent remote endpoints or fresh pooled outer transports.
type HTTPSProbeResult struct {
	RunID               string
	ServerID            string
	StrategyFingerprint string
	FirstResponseMillis [2]int64
}

type probeAccess struct {
	listen         netip.AddrPort
	user, password string
}

func (s LoopbackHTTPSProbe) validate() (*x509.Certificate, error) {
	validServerName := validName(s.ServerName)
	if address, err := netip.ParseAddr(s.ServerName); err == nil {
		validServerName = address.IsLoopback() && address.Zone() == ""
	}
	if !s.Target.IsValid() || !s.Target.Addr().IsLoopback() || s.Target.Addr().Zone() != "" || s.Target.Port() == 0 ||
		!validServerName || len(s.CertificateDER) == 0 || len(s.CertificateDER) > 8192 ||
		len(s.ExpectedBody) == 0 || len(s.ExpectedBody) > 4096 || s.Timeout <= 0 || s.Timeout > 15*time.Second {
		return nil, Error{InvalidProbe}
	}
	cert, err := x509.ParseCertificate(s.CertificateDER)
	if err != nil {
		return nil, Error{InvalidProbe}
	}
	return cert, nil
}

// ProbeLoopbackHTTPS measures only the exact owned ready generation. It does
// not renew its lease or mutate its health state. At most one probe is admitted
// per run. Stop, lease loss and Close cancel and join that probe before reporting
// owner cleanup. A stale generation can never measure or credit its replacement.
func (o *RuntimeOwner) ProbeLoopbackHTTPS(request context.Context, runID string, spec LoopbackHTTPSProbe) (HTTPSProbeResult, error) {
	if len(spec.CertificateDER) > 8192 || len(spec.ExpectedBody) > 4096 {
		return HTTPSProbeResult{}, Error{InvalidProbe}
	}
	spec.CertificateDER = append([]byte(nil), spec.CertificateDER...)
	spec.ExpectedBody = append([]byte(nil), spec.ExpectedBody...)
	cert, err := spec.validate()
	if err != nil {
		return HTTPSProbeResult{}, err
	}
	if request.Err() != nil {
		return HTTPSProbeResult{}, Error{Cancelled}
	}
	o.mu.Lock()
	run := o.run
	if o.closed || o.ctx.Err() != nil || run == nil || run.snapshot.RunID != runID || run.chain == nil || run.ctx.Err() != nil {
		o.mu.Unlock()
		return HTTPSProbeResult{}, Error{Inactive}
	}
	if _, ready := run.chain.engine.readyStatus(); !ready {
		o.mu.Unlock()
		return HTTPSProbeResult{}, Error{Inactive}
	}
	if run.probeBusy {
		o.mu.Unlock()
		return HTTPSProbeResult{}, Error{Busy}
	}
	run.probeBusy = true
	run.probes.Add(1)
	access := run.probe
	result := HTTPSProbeResult{RunID: runID, ServerID: run.snapshot.ServerID, StrategyFingerprint: run.snapshot.StrategyFingerprint}
	ctx, cancel := context.WithTimeout(run.ctx, spec.Timeout)
	o.mu.Unlock()
	stopRequest := context.AfterFunc(request, cancel)
	defer func() {
		stopRequest()
		cancel()
		o.mu.Lock()
		run.probeBusy = false
		o.mu.Unlock()
		run.probes.Done()
	}()
	for i := range result.FirstResponseMillis {
		duration, err := probeHTTPSRequest(ctx, access, spec, cert)
		if err != nil {
			if run.ctx.Err() != nil {
				return HTTPSProbeResult{}, Error{Inactive}
			}
			if request.Err() != nil {
				return HTTPSProbeResult{}, Error{Cancelled}
			}
			if probeDeadlineReached(ctx) {
				return HTTPSProbeResult{}, Error{ProbeTimeout}
			}
			return HTTPSProbeResult{}, err
		}
		result.FirstResponseMillis[i] = max(1, duration.Milliseconds())
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	_, ready := run.chain.engine.readyStatus()
	if o.run != run || o.closed || run.ctx.Err() != nil || !ready {
		return HTTPSProbeResult{}, Error{Inactive}
	}
	if request.Err() != nil {
		return HTTPSProbeResult{}, Error{Cancelled}
	}
	if probeDeadlineReached(ctx) {
		return HTTPSProbeResult{}, Error{ProbeTimeout}
	}
	return result, nil
}

// A socket's deadline can expire just before the context timer publishes Err.
// Check the shared monotonic deadline too, so that race cannot mislabel timeout
// as TLS failure or credit a response that completed outside its budget.
func probeDeadlineReached(ctx context.Context) bool {
	if ctx.Err() != nil {
		return true
	}
	deadline, ok := ctx.Deadline()
	return ok && !time.Now().Before(deadline)
}

func probeHTTPSRequest(ctx context.Context, access probeAccess, spec LoopbackHTTPSProbe, cert *x509.Certificate) (time.Duration, error) {
	started := time.Now()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", access.listen.String())
	if err != nil {
		return 0, Error{ProbeTransport}
	}
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(closed); _ = conn.Close() })
	defer func() {
		if !stop() {
			<-closed
		}
		_ = conn.Close()
	}()
	if deadline, ok := ctx.Deadline(); !ok {
		return 0, Error{InvalidProbe}
	} else if conn.SetDeadline(deadline) != nil {
		return 0, Error{ProbeTransport}
	}
	if err := probeSOCKSConnect(conn, access, spec.Target); err != nil {
		return 0, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	secure := tls.Client(conn, &tls.Config{RootCAs: roots, ServerName: spec.ServerName, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	if secure.HandshakeContext(ctx) != nil {
		return 0, Error{ProbeTLS}
	}
	state := secure.ConnectionState()
	if !state.HandshakeComplete || state.NegotiatedProtocol != "http/1.1" || len(state.PeerCertificates) == 0 || !bytes.Equal(state.PeerCertificates[0].Raw, spec.CertificateDER) {
		return 0, Error{ProbeTLS}
	}
	request, err := http.NewRequestWithContext(ctx, "GET", "https://"+spec.Target.String()+"/", nil)
	if err != nil {
		return 0, Error{InvalidProbe}
	}
	request.Close = true
	request.Header.Set("User-Agent", "Zarp-Loopback-Probe/1")
	request.Header.Set("Accept-Encoding", "identity")
	if request.Write(secure) != nil {
		return 0, Error{ProbeTransport}
	}
	// ReadResponse has no independent header bound. Cap the complete decrypted
	// response, including headers/chunk framing, before parsing. Body has its
	// own smaller limit. There is no redirect or decompression retry.
	reader := bufio.NewReader(io.LimitReader(secure, 16384))
	if _, err := reader.Peek(1); err != nil {
		return 0, Error{ProbeResponse}
	}
	firstByte := time.Since(started)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return 0, Error{ProbeResponse}
	}
	defer func() { _ = conn.Close(); _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" {
		return 0, Error{ProbeResponse}
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || !bytes.Equal(body, spec.ExpectedBody) {
		return 0, Error{ProbeResponse}
	}
	if ctx.Err() != nil {
		return 0, Error{ProbeTimeout}
	}
	return firstByte, nil
}

// Offer only authenticated SOCKS. x/net's general SOCKS helper also offers the
// unauthenticated method; a probe must never downgrade if that is selected.
func probeSOCKSConnect(conn net.Conn, access probeAccess, target netip.AddrPort) error {
	failure := Error{ProbeTransport}
	write := func(data []byte) bool {
		for len(data) > 0 {
			n, err := conn.Write(data)
			if err != nil || n <= 0 {
				return false
			}
			data = data[n:]
		}
		return true
	}
	if !write([]byte{5, 1, 2}) {
		return failure
	}
	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil || reply != [2]byte{5, 2} {
		return failure
	}
	auth := append([]byte{1, byte(len(access.user))}, []byte(access.user)...)
	auth = append(auth, byte(len(access.password)))
	auth = append(auth, []byte(access.password)...)
	if !write(auth) {
		return failure
	}
	if _, err := io.ReadFull(conn, reply[:]); err != nil || reply != [2]byte{1, 0} {
		return failure
	}
	kind := byte(1)
	if target.Addr().Is6() {
		kind = 4
	}
	address := append([]byte{5, 1, 0, kind}, target.Addr().AsSlice()...)
	address = binary.BigEndian.AppendUint16(address, target.Port())
	if !write(address) {
		return failure
	}
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil || header[0] != 5 || header[1] != 0 || header[2] != 0 {
		return failure
	}
	width := 4
	if header[3] == 4 {
		width = 16
	} else if header[3] != 1 {
		return failure
	}
	bound := make([]byte, width+2)
	if _, err := io.ReadFull(conn, bound); err != nil {
		return failure
	}
	ip, ok := netip.AddrFromSlice(bound[:width])
	if !ok || !ip.IsLoopback() && !ip.IsUnspecified() {
		return failure
	}
	return nil
}
