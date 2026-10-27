package warp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var registrationCandidate = RegistrationStrategy{ID: "tls-split", Mode: "split", Positions: []string{"1", "midsld"}}

var enrolledResponse = enrollmentFixture()

func enrollmentFixture() string {
	_, _, public, err := generateECKeyPair()
	if err != nil {
		panic(err)
	}
	peer := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}))
	data, _ := json.Marshal(peer)
	return strings.ReplaceAll(`{"id":"fixture-device","config":{"peers":[{"public_key":PUBLIC_KEY,"endpoint":{"v4":"162.159.198.1:443"}}],"interface":{"addresses":{"v4":"172.16.0.2","v6":"2606:4700:110::2"}}}}`, "PUBLIC_KEY", string(data))
}

func setupInput(op string, protected bool) AccountSetupRequest {
	r := AccountSetupRequest{Version: 1, Operation: op}
	if protected {
		r.Strategies = []RegistrationStrategy{registrationCandidate}
	}
	if op == "license" {
		r.License = "aB123456-abcdefgh-87654321"
	}
	return r
}

func sentHeaders(r *http.Request) {
	if trace := httptrace.ContextClientTrace(r.Context()); trace != nil && trace.WroteHeaders != nil {
		trace.WroteHeaders()
	}
}

func expectSetupCode(t *testing.T, err error, code string) {
	t.Helper()
	var e *SetupError
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("expected %s, got %v", code, err)
	}
}

func TestRegistrationFallbackProtectsAllStagesWithoutPersistingLicense(t *testing.T) {
	path := filepath.Join(t.TempDir(), "account.json")
	var choices, methods []string
	r := Registration{Path: path, DeviceName: "fixture", Factory: func(_ context.Context, s *RegistrationStrategy) (http.RoundTripper, error) {
		if s == nil {
			choices = append(choices, "plain")
			return accountTransport(func(*http.Request) (*http.Response, error) { return nil, errors.New("TLS blocked") }), nil
		}
		choices = append(choices, s.ID)
		return accountTransport(func(req *http.Request) (*http.Response, error) {
			if req.URL.Host != registrationHost || req.URL.Scheme != "https" {
				t.Fatal("API origin escaped fixed policy")
			}
			methods = append(methods, req.Method)
			sentHeaders(req)
			switch req.Method {
			case "POST":
				return accountResponse(200, `{"id":"fixture-device","token":"private-token"}`), nil
			case "PATCH":
				return accountResponse(200, enrolledResponse), nil
			case "PUT":
				if req.Header.Get("Authorization") != "Bearer private-token" {
					t.Fatal("wrong account")
				}
				return accountResponse(200, `{}`), nil
			case "GET":
				return accountResponse(200, `{"account_type":"unlimited"}`), nil
			}
			t.Fatal("unexpected method")
			return nil, nil
		}), nil
	}}
	status, err := r.Do(context.Background(), setupInput("license", true))
	if err != nil || !status.AccountRegistered || !status.APIProtected || !status.LicenseApplied || status.AccountType != AccountUnlimited {
		t.Fatalf("setup: %+v %v", status, err)
	}
	if !reflect.DeepEqual(choices, []string{"plain", "tls-split"}) || !reflect.DeepEqual(methods, []string{"POST", "PATCH", "PUT", "GET"}) {
		t.Fatalf("scope lost: %v %v", choices, methods)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 || strings.Contains(string(data), "aB123456") {
		t.Fatal("private storage policy failed")
	}
	public, _ := json.Marshal(status)
	if strings.Contains(string(public), "private-") || strings.Contains(string(public), "fixture-device") {
		t.Fatal("public result leaked credentials")
	}
	if AccountState(path) != "ready" {
		t.Fatal("account not committed")
	}
	if _, err := os.Stat(path + ".registration-pending"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("checkpoint not cleared")
	}
}

func TestRegistrationResumesEnrollmentWithoutCreatingAnotherAccount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "account.json")
	posts, patches := 0, 0
	var originalKey string
	canEnroll := false
	r := Registration{Path: path, Factory: func(context.Context, *RegistrationStrategy) (http.RoundTripper, error) {
		return accountTransport(func(req *http.Request) (*http.Response, error) {
			sentHeaders(req)
			if req.Method == "POST" {
				posts++
				return accountResponse(200, `{"id":"fixture-device","token":"private-token"}`), nil
			}
			patches++
			body, _ := io.ReadAll(req.Body)
			if originalKey == "" {
				originalKey = string(body)
			} else if originalKey != string(body) {
				t.Fatal("enrollment changed the pending key")
			}
			if !canEnroll {
				return nil, errors.New("connection lost")
			}
			return accountResponse(200, enrolledResponse), nil
		}), nil
	}}
	_, err := r.Do(context.Background(), setupInput("register", false))
	expectSetupCode(t, err, "account_network")
	if AccountState(path) != "pending" {
		t.Fatal("partial account was lost")
	}
	canEnroll = true
	result, err := r.Do(context.Background(), setupInput("register", false))
	if err != nil || !result.AccountRegistered || posts != 1 || patches != 2 {
		t.Fatalf("resume: posts=%d patches=%d %v", posts, patches, err)
	}
	if result.AccountType != AccountUnknown {
		t.Fatal("registration pretended to confirm an account tier")
	}
}

func TestRegistrationDoesNotReplayAnUncertainPost(t *testing.T) {
	path := filepath.Join(t.TempDir(), "account.json")
	calls := 0
	r := Registration{Path: path, Factory: func(context.Context, *RegistrationStrategy) (http.RoundTripper, error) {
		return accountTransport(func(req *http.Request) (*http.Response, error) {
			calls++
			sentHeaders(req)
			return nil, errors.New("lost response")
		}), nil
	}}
	for i := 0; i < 2; i++ {
		_, err := r.Do(context.Background(), setupInput("register", true))
		expectSetupCode(t, err, "account_uncertain")
	}
	if calls != 1 || AccountState(path) != "uncertain" {
		t.Fatal("uncertain creation was replayed")
	}
}

func TestRegistrationDoesNotRetryQuotaOrOverwriteDamagedStorage(t *testing.T) {
	for _, kind := range []string{"quota", "damaged", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "account.json")
			calls := 0
			switch kind {
			case "damaged":
				if err := os.WriteFile(path, []byte("private-corrupt-data"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink("missing-target", path); err != nil {
					t.Fatal(err)
				}
			}
			r := Registration{Path: path, Factory: func(context.Context, *RegistrationStrategy) (http.RoundTripper, error) {
				return accountTransport(func(req *http.Request) (*http.Response, error) {
					calls++
					sentHeaders(req)
					return accountResponse(429, `{"secret":"never expose"}`), nil
				}), nil
			}}
			_, err := r.Do(context.Background(), setupInput("register", true))
			if kind == "quota" {
				expectSetupCode(t, err, "account_rate_limited")
				if calls != 1 || AccountState(path) != "pending" {
					t.Fatal("quota was retried")
				}
			} else {
				expectSetupCode(t, err, "account_unavailable")
				if calls != 0 {
					t.Fatal("damaged storage granted network access")
				}
			}
		})
	}
}

func TestRegistrationCancellationJoinsRequestAndCannotWriteLate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "account.json")
	started, joined := make(chan struct{}), make(chan struct{})
	r := Registration{Path: path, Factory: func(context.Context, *RegistrationStrategy) (http.RoundTripper, error) {
		return accountTransport(func(req *http.Request) (*http.Response, error) {
			close(started)
			<-req.Context().Done()
			close(joined)
			return nil, req.Context().Err()
		}), nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := r.Do(ctx, setupInput("register", true)); done <- err }()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not join setup")
	}
	select {
	case <-joined:
	default:
		t.Fatal("setup returned before HTTP worker joined")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled request committed an account")
	}
	if AccountState(path) != "pending" {
		t.Fatal("pre-send cancellation was marked uncertain")
	}
}

func TestAcceptedLicenseRetriesOnlyConfirmation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "account.json")
	if err := writeConfig(path, accountFixture()); err != nil {
		t.Fatal(err)
	}
	puts, gets := 0, 0
	r := Registration{Path: path, Factory: func(_ context.Context, s *RegistrationStrategy) (http.RoundTripper, error) {
		return accountTransport(func(req *http.Request) (*http.Response, error) {
			sentHeaders(req)
			if req.Method == "PUT" {
				puts++
				return accountResponse(200, `{}`), nil
			}
			gets++
			if s == nil {
				return nil, errors.New("status blocked")
			}
			return accountResponse(200, `{"warp_plus":true}`), nil
		}), nil
	}}
	result, err := r.Do(context.Background(), setupInput("license", true))
	if err != nil || puts != 1 || gets != 2 || result.AccountType != AccountPlus || !result.LicenseApplied || !result.APIProtected {
		t.Fatalf("license confirmation: %+v %v %d/%d", result, err, puts, gets)
	}
}

func TestUncertainLicenseIsNeverReappliedDuringRecovery(t *testing.T) {
	for _, tier := range []string{"free", "plus"} {
		t.Run(tier, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "account.json")
			if err := writeConfig(path, accountFixture()); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(path)
			puts, gets := 0, 0
			r := Registration{Path: path, Factory: func(context.Context, *RegistrationStrategy) (http.RoundTripper, error) {
				return accountTransport(func(req *http.Request) (*http.Response, error) {
					sentHeaders(req)
					if req.Method == "PUT" {
						puts++
						return nil, errors.New("license response lost")
					}
					gets++
					return accountResponse(200, `{"account_type":"`+tier+`"}`), nil
				}), nil
			}}
			result, err := r.Do(context.Background(), setupInput("license", true))
			if tier == "free" {
				expectSetupCode(t, err, "license_uncertain")
			} else if err != nil || result.AccountType != AccountPlus {
				t.Fatalf("existing premium state was lost: %+v %v", result, err)
			}
			if puts != 1 || gets != 1 {
				t.Fatal("uncertain license was replayed")
			}
			after, _ := os.ReadFile(path)
			if string(before) != string(after) {
				t.Fatal("account identity was replaced")
			}
		})
	}
}

func TestRegistrationTLSUsesNativeSplitAndRetainsCertificateChecks(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("owned-loopback")) }))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	for _, item := range []struct {
		mode, host string
		trusted    bool
		want       bool
	}{{"split", "example.com", true, true}, {"disorder", "example.com", true, true}, {"split", "wrong.example", true, false}, {"split", "example.com", false, false}} {
		t.Run(item.mode+item.host+string(rune('0'+boolInt(item.trusted))), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			spec, _ := ParseDesync(item.mode + ":1,midsld")
			trust := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
			if item.trusted {
				trust.RootCAs = pool
			}
			conn, err := registrationTLS(ctx, raw, spec, item.host, trust)
			if conn != nil {
				defer conn.Close()
			}
			if (err == nil) != item.want {
				t.Fatalf("TLS policy: %v", err)
			}
			if !item.want {
				return
			}
			if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			response, err := io.ReadAll(conn)
			if err != nil || !strings.Contains(string(response), "owned-loopback") {
				t.Fatalf("TLS application traffic: %v", err)
			}
		})
	}
}

func TestRegistrationTransportJoinsADetachedDialBeforeRelease(t *testing.T) {
	transport := newRegistrationHTTPTransport()
	started, cancelled, release, joined := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	transport.DialTLSContext = transport.trackDial(func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		close(cancelled)
		<-release
		close(joined)
		return nil, ctx.Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://owned-fixture.invalid/", nil)
	returned := make(chan error, 1)
	go func() { _, err := (&http.Client{Transport: transport}).Do(req); returned <- err }()
	<-started
	cancel()
	select {
	case err := <-returned:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("HTTP cancellation did not return")
	}
	closed := make(chan struct{})
	go func() { transport.CloseIdleConnections(); close(closed) }()
	<-cancelled
	select {
	case <-closed:
		t.Fatal("transport released an unjoined dial")
	default:
	}
	close(release)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("owned dial cleanup did not join")
	}
	select {
	case <-joined:
	default:
		t.Fatal("dial worker still running")
	}
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
