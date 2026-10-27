package daemon

// All connections/runners are private fakes. No real opener, TUN, production
// IPC, account registration or system command is invoked by these tests.
import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/feg55/zarp-macos/zarpd/ipc"
	"github.com/feg55/zarp-macos/zarpd/route"
	"github.com/feg55/zarp-macos/zarpd/warp"
	"golang.zx2c4.com/wireguard/tun"
)

type gatedClose struct {
	*fakeConn
	started, release       chan struct{}
	startOnce, releaseOnce sync.Once
	calls                  atomic.Int32
	failure                error
}

func (c *gatedClose) Close() error {
	c.calls.Add(1)
	c.startOnce.Do(func() { close(c.started) })
	<-c.release
	_ = c.fakeConn.Close()
	return c.failure
}
func (c *gatedClose) Name() string { panic("status/teardown must use the published name snapshot") }
func (c *gatedClose) unblock()     { c.releaseOnce.Do(func() { close(c.release) }) }

func gateConnection(t *testing.T, h *harness, id string) *gatedClose {
	t.Helper()
	c := &gatedClose{fakeConn: h.opener.conn(0), started: make(chan struct{}), release: make(chan struct{})}
	h.m.mu.Lock()
	h.m.conns[id].conn = c
	h.m.mu.Unlock()
	t.Cleanup(c.unblock)
	return c
}

func signalWithin(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("owned fake operation did not reach its barrier")
	}
}

func errorWithin(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("owned fake operation did not finish")
		return nil
	}
}

func remainsBlocked(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("operation completed before owned cleanup: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
}

func TestNetworkBusyIncludesOpeningScanAndTerminalShutdown(t *testing.T) {
	h := newHarness(t, time.Minute)
	if h.status(t).NetworkBusy {
		t.Fatal("new fake manager is not idle")
	}
	h.opener.block = make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := h.call(t, ctx, "open", scanTest); done <- err }()
	waitFor(t, "dial admission", func() bool { return h.opener.seen.Load() == 1 })
	if st := h.status(t); st.Connected || !st.NetworkBusy {
		t.Fatalf("opening appears idle: %+v", st)
	}
	cancel()
	if codeOf(errorWithin(t, done)) != ipc.CodeCancelled {
		t.Fatal("cancelled dial was accepted")
	}
	if h.status(t).NetworkBusy {
		t.Fatal("cancelled dial never released activity")
	}
	close(h.opener.block)
	opened := h.open(t, scanTest)
	if st := h.status(t); st.Connected || !st.NetworkBusy {
		t.Fatalf("scan appears idle/adoptable: %+v", st)
	}
	if _, err := h.call(t, context.Background(), "close", ipc.CloseParams{ConnectionID: opened.ConnectionID}); err != nil {
		t.Fatal(err)
	}
	if h.status(t).NetworkBusy {
		t.Fatal("successful joined close did not become idle")
	}
	if err := h.m.CloseAll(); err != nil {
		t.Fatal(err)
	}
	if !h.status(t).NetworkBusy {
		t.Fatal("terminal manager must not advertise reusable idle state")
	}
	if _, err := h.call(t, context.Background(), "open", persistent); codeOf(err) != ipc.CodeCancelled {
		t.Fatal("stopped manager revived")
	}
	if h.opener.seen.Load() != 2 {
		t.Fatal("stopped manager invoked opener")
	}
}

func TestConcurrentCloseAndReplacementJoinTheSameTeardown(t *testing.T) {
	h := newHarness(t, time.Minute)
	opened := h.open(t, persistent)
	c := gateConnection(t, h, opened.ConnectionID)
	closeCall := func(done chan<- error) {
		_, err := h.call(t, context.Background(), "close", ipc.CloseParams{ConnectionID: opened.ConnectionID})
		done <- err
	}
	first, second := make(chan error, 1), make(chan error, 1)
	go closeCall(first)
	signalWithin(t, c.started)
	go closeCall(second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	replacement := make(chan error, 1)
	go func() { _, err := h.call(t, ctx, "open", persistent); replacement <- err }()
	waitFor(t, "replacement admission", func() bool { h.m.mu.Lock(); defer h.m.mu.Unlock(); return h.m.opening == 1 })
	if st := h.status(t); st.Connected || !st.NetworkBusy {
		t.Fatalf("cleanup appears idle or adoptable: %+v", st)
	}
	remainsBlocked(t, first)
	remainsBlocked(t, second)
	remainsBlocked(t, replacement)
	if h.opener.seen.Load() != 1 {
		t.Fatal("replacement touched network before cleanup")
	}
	cancel()
	c.unblock()
	if err := errorWithin(t, first); err != nil {
		t.Fatal(err)
	}
	if err := errorWithin(t, second); err != nil {
		t.Fatal(err)
	}
	if codeOf(errorWithin(t, replacement)) != ipc.CodeCancelled {
		t.Fatal("cancelled replacement ran")
	}
	if c.calls.Load() != 1 || h.opener.seen.Load() != 1 {
		t.Fatal("cleanup repeated or cancelled replacement dialed")
	}
	if h.status(t).NetworkBusy {
		t.Fatal("joined cleanup did not release activity")
	}
	fresh := h.open(t, persistent)
	_, _ = h.call(t, context.Background(), "close", ipc.CloseParams{ConnectionID: opened.ConnectionID})
	if st := h.status(t); !st.Connected || st.ConnectionID != fresh.ConnectionID {
		t.Fatal("stale close touched replacement")
	}
	if err := h.m.CloseAll(); err != nil {
		t.Fatal(err)
	}
}

func TestNaturalLossCannotRaceAReplacementPastCleanup(t *testing.T) {
	h := newHarness(t, time.Minute)
	opened := h.open(t, persistent)
	c := gateConnection(t, h, opened.ConnectionID)
	c.fakeConn.die(errors.New("fake transport loss"))
	signalWithin(t, c.started)
	if st := h.status(t); st.Connected || !st.NetworkBusy || st.LastLoss == nil {
		t.Fatalf("invalid loss state: %+v", st)
	}
	done := make(chan error, 1)
	go func() { _, err := h.call(t, context.Background(), "open", persistent); done <- err }()
	remainsBlocked(t, done)
	if h.opener.seen.Load() != 1 {
		t.Fatal("loss cleanup overlapped another tunnel")
	}
	c.unblock()
	if err := errorWithin(t, done); err != nil {
		t.Fatal(err)
	}
	if st := h.status(t); !st.Connected || st.ConnectionID == opened.ConnectionID || st.LastLoss != nil {
		t.Fatalf("replacement did not publish: %+v", st)
	}
	if c.calls.Load() != 1 {
		t.Fatal("loss teardown repeated")
	}
	if err := h.m.CloseAll(); err != nil {
		t.Fatal(err)
	}
}

func TestShutdownCancelsAndJoinsLateDialAndRefusesQueuedOpens(t *testing.T) {
	h := newHarness(t, time.Minute)
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	late := newFakeConn("fake-utun")
	h.m.cfg.Opener = openerFunc(func(ctx context.Context, _ ipc.OpenParams) (Conn, OpenInfo, error) {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		<-release
		return late, OpenInfo{UtunName: "fake-utun"}, nil
	})
	first, queued := make(chan error, 1), make(chan error, 1)
	go func() { _, err := h.call(t, context.Background(), "open", persistent); first <- err }()
	signalWithin(t, entered)
	go func() { _, err := h.call(t, context.Background(), "open", persistent); queued <- err }()
	waitFor(t, "queued admission", func() bool { h.m.mu.Lock(); defer h.m.mu.Unlock(); return h.m.opening == 2 })
	shutdown, otherShutdown := make(chan error, 1), make(chan error, 1)
	go func() { shutdown <- h.m.CloseAll() }()
	signalWithin(t, cancelled)
	go func() { otherShutdown <- h.m.CloseAll() }()
	remainsBlocked(t, shutdown)
	remainsBlocked(t, otherShutdown)
	if codeOf(errorWithin(t, queued)) != ipc.CodeCancelled {
		t.Fatal("queued open survived shutdown")
	}
	unblock()
	if codeOf(errorWithin(t, first)) != ipc.CodeCancelled {
		t.Fatal("late dial was published")
	}
	if err := errorWithin(t, shutdown); err != nil {
		t.Fatal(err)
	}
	if err := errorWithin(t, otherShutdown); err != nil {
		t.Fatal(err)
	}
	if late.closeCount() != 1 {
		t.Fatal("shutdown did not join unpublished connection close")
	}
	if st := h.status(t); st.Connected || !st.NetworkBusy {
		t.Fatal("shutdown reported active/admissible connection")
	}
}

func TestCleanupFailureStaysBusyAndBlocksOpenRestartAndRepeatedTeardown(t *testing.T) {
	h := newHarness(t, time.Minute)
	opened := h.open(t, persistent)
	c := gateConnection(t, h, opened.ConnectionID)
	c.failure = errors.New("private-path-or-key must not cross IPC")
	c.unblock()
	for i := 0; i < 2; i++ {
		_, err := h.call(t, context.Background(), "close", ipc.CloseParams{ConnectionID: opened.ConnectionID})
		if codeOf(err) != ipc.CodeInternal || strings.Contains(err.Error(), "private-") {
			t.Fatal("cleanup uncertainty lost or leaked")
		}
	}
	if st := h.status(t); st.Connected || !st.NetworkBusy {
		t.Fatal("failed cleanup became idle/adoptable")
	}
	if _, err := h.call(t, context.Background(), "open", persistent); codeOf(err) != ipc.CodeInternal {
		t.Fatal("failed cleanup allowed replacement")
	}
	if _, err := h.call(t, context.Background(), "restart", nil); codeOf(err) != ipc.CodeInternal {
		t.Fatal("failed cleanup acknowledged restart")
	}
	if c.calls.Load() != 1 || h.opener.seen.Load() != 1 || h.restarts.Load() != 0 {
		t.Fatal("uncertain cleanup was retried or bypassed")
	}
}

func TestUnpublishedAndStartupCleanupFailuresNeverAdvertiseIdle(t *testing.T) {
	for _, source := range []string{"startup", "opener", "late-cancel"} {
		t.Run(source, func(t *testing.T) {
			h := newHarness(t, time.Minute)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch source {
			case "startup":
				h.m = NewManager(Config{Accounts: h.accounts, Opener: h.opener, Measurer: h.measurer, CleanupIncomplete: true})
			case "opener":
				h.m.cfg.Opener = openerFunc(func(context.Context, ipc.OpenParams) (Conn, OpenInfo, error) {
					return nil, OpenInfo{}, errCleanupIncomplete
				})
			case "late-cancel":
				c := &gatedClose{fakeConn: newFakeConn("fake"), started: make(chan struct{}), release: make(chan struct{}), failure: errors.New("private detail")}
				c.unblock()
				h.m.cfg.Opener = openerFunc(func(context.Context, ipc.OpenParams) (Conn, OpenInfo, error) { cancel(); return c, OpenInfo{}, nil })
			}
			if _, err := h.call(t, ctx, "open", persistent); codeOf(err) != ipc.CodeInternal {
				t.Fatalf("cleanup uncertainty lost: %v", err)
			}
			if st := h.status(t); st.Connected || !st.NetworkBusy {
				t.Fatal("uncertain cleanup became idle")
			}
			if _, err := h.call(t, context.Background(), "open", persistent); codeOf(err) != ipc.CodeInternal {
				t.Fatal("uncertain state admitted another open")
			}
		})
	}
}

type heldAccounts struct {
	Accounts
	entered, release chan struct{}
}

func (a heldAccounts) Has() bool { close(a.entered); <-a.release; return true }

func TestBlockedAccountSnapshotDoesNotHoldTheTunnelRegistryLock(t *testing.T) {
	h := newHarness(t, time.Minute)
	opened := h.open(t, persistent)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	h.m.cfg.Accounts = heldAccounts{Accounts: h.accounts, entered: entered, release: release}
	status := make(chan ipc.StatusResult, 1)
	go func() { status <- h.m.Status() }()
	signalWithin(t, entered)
	done := make(chan error, 1)
	go func() {
		_, err := h.call(t, context.Background(), "close", ipc.CloseParams{ConnectionID: opened.ConnectionID})
		done <- err
	}()
	if err := errorWithin(t, done); err != nil {
		t.Fatal(err)
	}
	unblock()
	select {
	case result := <-status:
		if result.Connected || result.NetworkBusy {
			t.Fatal("status missed completed close")
		}
	case <-time.After(time.Second):
		t.Fatal("status snapshot did not join")
	}
}

type closeOnlyDevice struct {
	tun.Device
	calls   atomic.Int32
	failure error
}

func (d *closeOnlyDevice) Close() error { d.calls.Add(1); return d.failure }

type cleanupRunner func(string, ...string) (string, error)

func (f cleanupRunner) Run(name string, args ...string) (string, error) { return f(name, args...) }

func TestRealConnectionCloseRetainsDeviceOrRouteFailureAcrossConcurrentCallers(t *testing.T) {
	for _, failure := range []string{"device", "route"} {
		t.Run(failure, func(t *testing.T) {
			dev := &closeOnlyDevice{}
			if failure == "device" {
				dev.failure = errors.New("private device error")
			}
			c := &realConn{dev: dev, session: &warp.Session{}, hostRoute: failure == "route", logf: func(string, ...any) {}}
			c.router = route.New(cleanupRunner(func(string, ...string) (string, error) { return "", errors.New("private route error") }))
			var workers sync.WaitGroup
			for i := 0; i < 12; i++ {
				workers.Add(1)
				go func() {
					defer workers.Done()
					if err := c.Close(); !errors.Is(err, errCleanupIncomplete) || strings.Contains(err.Error(), "private") {
						t.Error("cleanup failure lost or leaked")
					}
				}()
			}
			workers.Wait()
			if dev.calls.Load() != 1 {
				t.Fatal("device close repeated")
			}
		})
	}
}
