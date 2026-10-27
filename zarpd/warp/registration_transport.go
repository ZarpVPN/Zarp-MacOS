package warp

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

const registrationHost = "api.cloudflareclient.com"

// net/http can return a cancelled request while its detached dial still runs.
// Each setup attempt owns and joins those dials before another attempt starts.
type RegistrationHTTPTransport struct {
	*http.Transport
	mu       sync.Mutex
	closed   bool
	dials    sync.WaitGroup
	lifetime context.Context
	cancel   context.CancelFunc
}

func newRegistrationHTTPTransport() *RegistrationHTTPTransport {
	ctx, cancel := context.WithCancel(context.Background())
	return &RegistrationHTTPTransport{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second, MaxResponseHeaderBytes: 32768}, lifetime: ctx, cancel: cancel}
}

func (t *RegistrationHTTPTransport) trackDial(dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(parent context.Context, network, address string) (net.Conn, error) {
		t.mu.Lock()
		if t.closed {
			t.mu.Unlock()
			return nil, context.Canceled
		}
		t.dials.Add(1)
		t.mu.Unlock()
		defer t.dials.Done()
		ctx, cancel := context.WithCancel(parent)
		defer cancel()
		stop := context.AfterFunc(t.lifetime, cancel)
		defer stop()
		if t.lifetime.Err() != nil {
			cancel()
		}
		return dial(ctx, network, address)
	}
}

func (t *RegistrationHTTPTransport) CloseIdleConnections() {
	t.mu.Lock()
	t.closed = true
	t.cancel()
	t.mu.Unlock()
	t.Transport.CloseIdleConnections()
	t.dials.Wait()
}

// NewRegistrationTransport fixes the API origin and retains normal TLS trust.
// The daemon supplies the socket policy; IPC cannot supply an address or proxy.
func NewRegistrationTransport(strategy *RegistrationStrategy, dialer *net.Dialer) (*RegistrationHTTPTransport, error) {
	if strategy != nil && !strategy.Validate() {
		return nil, &SetupError{Code: "bad_request"}
	}
	if dialer == nil {
		dialer = &net.Dialer{Timeout: 10 * time.Second}
	}
	var spec *DesyncSpec
	if strategy != nil {
		var err error
		spec, err = ParseDesync(strategy.Mode + ":" + joinPositions(strategy.Positions))
		if err != nil {
			return nil, &SetupError{Code: "bad_request"}
		}
	}
	transport := newRegistrationHTTPTransport()
	transport.DialTLSContext = transport.trackDial(func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != registrationHost+":443" {
			return nil, &SetupError{Code: "bad_request"}
		}
		lookup, cancel := context.WithTimeout(ctx, 5*time.Second)
		ips, err := net.DefaultResolver.LookupNetIP(lookup, "ip", registrationHost)
		cancel()
		if err != nil || len(ips) == 0 {
			ips = []netip.Addr{netip.MustParseAddr("162.159.137.105"), netip.MustParseAddr("162.159.138.105"), netip.MustParseAddr("2606:4700:7::a29f:8969"), netip.MustParseAddr("2606:4700:7::a29f:8a69")}
		}
		var last error
		for i, ip := range ips {
			if i >= 16 {
				break
			}
			ip = ip.Unmap()
			if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			raw, err := dialer.DialContext(ctx, "tcp", netip.AddrPortFrom(ip, 443).String())
			if err != nil {
				var fixed *SetupError
				if errors.As(err, &fixed) {
					return nil, fixed
				}
				last = err
				continue
			}
			conn, err := registrationTLS(ctx, raw, spec, registrationHost, nil)
			if err == nil {
				return conn, nil
			}
			last = err
			var certificate *tls.CertificateVerificationError
			if errors.As(err, &certificate) {
				return nil, err
			}
		}
		if last == nil {
			last = &SetupError{Code: "account_network", Retryable: true}
		}
		return nil, last
	})
	return transport, nil
}

func joinPositions(values []string) string {
	var out string
	for i, value := range values {
		if i > 0 {
			out += ","
		}
		out += value
	}
	return out
}

// registrationTLS also serves owned loopback fixtures. A nil trust configuration
// uses the system roots; production always supplies nil here.
func registrationTLS(ctx context.Context, raw net.Conn, spec *DesyncSpec, host string, trust *tls.Config) (net.Conn, error) {
	config := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	if trust != nil {
		config = trust.Clone()
		config.ServerName = host
		config.InsecureSkipVerify = false
	}
	var connection net.Conn = raw
	if spec != nil {
		tcp, ok := raw.(*net.TCPConn)
		if !ok {
			raw.Close()
			return nil, &SetupError{Code: "strategy_unapplied"}
		}
		connection = &registrationHelloConn{Conn: NewDesyncConn(tcp, spec, host), spec: spec, host: host}
	}
	secured := tls.Client(connection, config)
	if err := secured.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return secured, nil
}

type registrationHelloConn struct {
	net.Conn
	spec *DesyncSpec
	host string
	once sync.Once
}

func (c *registrationHelloConn) Write(data []byte) (int, error) {
	valid := true
	c.once.Do(func() { valid = len(data) >= 6 && data[0] == 0x16 && len(splitPositions(data, c.spec.Pos, c.host)) > 0 })
	if !valid {
		return 0, &SetupError{Code: "strategy_unapplied", Retryable: true}
	}
	return c.Conn.Write(data)
}
