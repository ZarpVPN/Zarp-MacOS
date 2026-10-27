package warp

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func requireDialTimeoutPhase(t *testing.T, err error, phase string) {
	t.Helper()
	var failure *DialError
	if !errors.As(err, &failure) || failure.Phase != phase {
		t.Fatalf("timeout context = %+v, want phase %s (error: %v)", failure, phase, err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("dial deadline lost its error type: %v", err)
	}
}

func TestH2TimeoutRetainsTLSPhaseBeforeHandshakeCompletes(t *testing.T) {
	endpoint, closed := silentServer(t)
	session, err := DialH2(context.Background(), context.Background(), &net.Dialer{}, endpoint,
		h2TestConfig(), nil, 200*time.Millisecond)
	if session != nil || err == nil {
		t.Fatal("silent peer established a session")
	}
	requireDialTimeoutPhase(t, err, "tls")
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("timed-out TLS socket was not closed")
	}
}

func TestH2TimeoutAfterTLSDoesNotImplyAConnectResponse(t *testing.T) {
	clientTLS, serverTLS := masqueLoopbackTLS(t)
	serverTLS.NextProtos = []string{"h2"}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	closed := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			closed <- err
			return
		}
		defer raw.Close()
		raw.SetDeadline(time.Now().Add(3 * time.Second))
		peer := tls.Server(raw, serverTLS)
		if err := peer.Handshake(); err != nil {
			closed <- err
			return
		}
		// Accept authenticated TLS but never send the HTTP2 preface/SETTINGS.
		_, _ = io.Copy(io.Discard, peer)
		closed <- nil
	}()
	session, err := DialH2(context.Background(), context.Background(), &net.Dialer{}, listener.Addr().(*net.TCPAddr),
		clientTLS, nil, 300*time.Millisecond)
	if session != nil || err == nil {
		t.Fatal("peer without HTTP2 SETTINGS established a session")
	}
	// HTTP2 permits request headers before peer SETTINGS. This phase records
	// local header writes, rather than evidence of a peer response.
	requireDialTimeoutPhase(t, err, "connect_ip")
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed-out HTTP2 socket was not closed")
	}
}

func TestH2TimeoutAfterRequestHeadersRetainsConnectIPPhase(t *testing.T) {
	clientTLS, serverTLS := masqueLoopbackTLS(t)
	requested := make(chan struct{}, 1)
	fixture := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested <- struct{}{}
		<-r.Context().Done()
	}))
	fixture.EnableHTTP2, fixture.TLS = true, serverTLS
	fixture.StartTLS()
	defer fixture.Close()
	session, err := DialH2(context.Background(), context.Background(), &net.Dialer{}, fixture.Listener.Addr().(*net.TCPAddr),
		clientTLS, nil, 300*time.Millisecond)
	if session != nil || err == nil {
		t.Fatal("peer without a CONNECT response established a session")
	}
	requireDialTimeoutPhase(t, err, "connect_ip")
	select {
	case <-requested:
	default:
		t.Fatal("the fixture never received the CONNECT request")
	}
}
