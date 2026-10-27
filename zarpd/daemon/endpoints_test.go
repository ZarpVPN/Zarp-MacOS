package daemon

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	usqueconfig "github.com/Diniboy1123/usque/config"

	"github.com/feg55/zarp-macos/zarpd/ipc"
	"github.com/feg55/zarp-macos/zarpd/warp"
)

func TestIsolatedEndpointRotation(t *testing.T) {
	// Windows Zarp's Warp.NextEndpoint, value for value: addresses vary fastest, then ports.
	want := []string{
		"162.159.198.1:443", "162.159.198.2:443",
		"162.159.198.1:500", "162.159.198.2:500",
		"162.159.198.1:1701", "162.159.198.2:1701",
		"162.159.198.1:4500", "162.159.198.2:4500",
		"162.159.198.1:4443", "162.159.198.2:4443",
		"162.159.198.1:8443", "162.159.198.2:8443",
		"162.159.198.1:443", // the pool wraps after 12
	}
	for n, w := range want {
		if got := isolatedEndpoint(n).String(); got != w {
			t.Errorf("H3 endpoint #%d = %s, want %s", n, got, w)
		}
	}
}

func TestConsecutiveTestsAlwaysUseDifferentEndpoints(t *testing.T) {
	// The point of "isolate tests": a test and the re-check right after it must not share a
	// 5-tuple. ZarpEngine numbers its tokens consecutively.
	for n := 0; n < 40; n++ {
		if isolatedEndpoint(n) == isolatedEndpoint(n+1) {
			t.Fatalf("HTTP3 endpoints #%d and #%d are identical", n, n+1)
		}
	}
}

func TestEveryPoolEndpointPassesTheDaemonsOwnValidation(t *testing.T) {
	// The pool must never produce an address the same daemon would refuse if a client asked for it.
	for n := 0; n < 30; n++ {
		ep := isolatedEndpoint(n).String()
		p := ipc.OpenParams{Transport: "masqueH3", Endpoint: ep, FakeSteps: []ipc.FakeStep{{Blob: "quic_google", Repeats: 1}}}
		if err := p.Validate(); err != nil {
			t.Errorf("pool endpoint %s (#%d) fails validation: %v", ep, n, err)
		}
	}
}

func TestHotspotH2IsolationHonorsDedicatedAccountEndpoint(t *testing.T) {
	// Tokens from the failed session must not alternate onto the HTTP3 .1 address.
	for _, host := range []string{"", "162.159.198.2", "162.159.198.7"} {
		cfg := &usqueconfig.Config{EndpointV4: "162.159.198.1", EndpointH2V4: host}
		want := host
		if want == "" {
			want = usqueconfig.DefaultEndpointH2V4
		}
		for _, n := range []int{14, 15, 18, 19, 20} {
			p := ipc.OpenParams{Transport: "masqueH2", Endpoint: fmt.Sprintf("isolated-%d", n)}
			got, err := resolveEndpoint(p, cfg)
			if err != nil || got.String() != want+":443" {
				t.Fatalf("%+v: got %v, %v", p, got, err)
			}
		}
	}
	_, err := resolveEndpoint(ipc.OpenParams{Transport: "masqueH2", Endpoint: "isolated-14"}, &usqueconfig.Config{EndpointH2V4: "invalid"})
	if err == nil {
		t.Fatal("invalid dedicated endpoint silently fell back to the HTTP3 pool")
	}
	got, err := resolveEndpoint(ipc.OpenParams{Transport: "masqueH2", Endpoint: "162.159.192.9:4443"}, &usqueconfig.Config{})
	if err != nil || got.String() != "162.159.192.9:4443" {
		t.Fatal("explicit custom endpoint lost", got, err)
	}
}

func TestResolveEndpoint(t *testing.T) {
	cfg := &usqueconfig.Config{EndpointV4: "162.159.198.7", EndpointH2V4: "162.159.198.2"}
	tests := []struct {
		name string
		p    ipc.OpenParams
		want string
	}{
		{"account default, H3", ipc.OpenParams{Transport: "masqueH3"}, "162.159.198.7:443"},
		{"account default, H2 uses the H2 endpoint", ipc.OpenParams{Transport: "masqueH2"}, "162.159.198.2:443"},
		{"isolation token, H3", ipc.OpenParams{Transport: "masqueH3", Endpoint: "isolated-3"}, "162.159.198.2:500"},
		{"isolation token, H2", ipc.OpenParams{Transport: "masqueH2", Endpoint: "isolated-3"}, "162.159.198.2:443"},
		{"explicit ip", ipc.OpenParams{Transport: "masqueH3", Endpoint: "162.159.192.5"}, "162.159.192.5:443"},
		{"explicit ip:port", ipc.OpenParams{Transport: "masqueH3", Endpoint: "162.159.192.5:4500"}, "162.159.192.5:4500"},
	}
	for _, tt := range tests {
		got, err := resolveEndpoint(tt.p, cfg)
		if err != nil || got.String() != tt.want {
			t.Errorf("%s: got %v, %v want %s", tt.name, got, err, tt.want)
		}
	}
	if _, err := resolveEndpoint(ipc.OpenParams{Transport: "masqueH3"}, &usqueconfig.Config{EndpointV4: "not-an-ip"}); err == nil {
		t.Error("a corrupt account endpoint must be an error, not a zero address")
	}
}

type timeoutNetErr struct{}

func (timeoutNetErr) Error() string   { return "i/o timeout" }
func (timeoutNetErr) Timeout() bool   { return true }
func (timeoutNetErr) Temporary() bool { return true }

var _ net.Error = timeoutNetErr{}

func TestDialErrToConnError(t *testing.T) {
	timedOut := []error{
		context.DeadlineExceeded,
		fmt.Errorf("wrapped: %w", context.DeadlineExceeded),
		timeoutNetErr{},
		errors.New("DialH3: connect-ip: failed to read response: http3: connect timeout"),
		errors.New("timeout after 15s: context canceled"),
		errors.New("context deadline exceeded"),
	}
	for _, e := range timedOut {
		ce := dialErrToConnError(e).(*ipc.ConnError)
		if !ce.TimedOut {
			t.Errorf("%v should count as a timeout", e)
		}
	}
	for _, e := range []error{errors.New("connection refused"), errors.New("tls: access denied"), context.Canceled} {
		ce := dialErrToConnError(e).(*ipc.ConnError)
		if ce.TimedOut || !strings.Contains(ce.Message, e.Error()) {
			t.Errorf("%v: %+v", e, ce)
		}
	}
}

func TestPeerPinRejectionAndPhaseSurviveNestedOpenErrorConversion(t *testing.T) {
	verification := x509.CertificateInvalidError{Reason: x509.NoValidChains, Detail: "remote endpoint has a different public key than what we trust in config.json"}
	native := &warp.DialError{Phase: "tls", Err: fmt.Errorf("HTTPS CONNECT: %w", verification)}
	converted := dialErrToConnError(native)
	converted = dialErrToConnError(fmt.Errorf("open failed: %w", converted))
	failure := converted.(*ipc.ConnError)
	if failure.Code != ipc.CodePeerKeyMismatch || failure.TimedOut || failure.Connection == nil || failure.Connection.Phase != "tls" {
		t.Fatalf("transport failure was flattened into generic text: %+v", failure)
	}
	if !strings.Contains(failure.Message, verification.Detail) {
		t.Fatal("original reason lost")
	}
	ordinary := dialErrToConnError(&warp.DialError{Phase: "tcp", Err: context.DeadlineExceeded}).(*ipc.ConnError)
	if !ordinary.TimedOut || ordinary.Connection.Phase != "tcp" || ordinary.Code == ipc.CodePeerKeyMismatch {
		t.Fatal("ordinary timeout became a trust failure", ordinary)
	}
}
