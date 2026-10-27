// Package daemon is zarpd's brain: the registry of live tunnels and the IPC method handlers
// (ping, status, register, open, close, measure, logs, restart) that Zarp.app drives.
//
// What the registry exists to guarantee — each of these was a real failure before:
//
//   - One tunnel at a time. Every connection shares the one measurement route, so a second
//     tunnel cannot coexist with the first. A new `open` therefore closes whatever is still open
//     (the previous persistent connection, or a test connection whose client crashed before it
//     could close it) instead of failing on a stale route and staying broken until a restart.
//   - A test connection can't outlive its owner. Non-persistent connections carry a lease; the
//     app closes them within seconds, so one still open after the lease belongs to a client that
//     is gone.
//   - A tunnel that dies on its own is noticed. When the data plane stops (the MASQUE session
//     drops, the network changes), the connection is torn down — routes and DNS restored, the
//     machine fails open — and reported as lost, instead of lingering as "connected".
//   - A caller that goes away mid-open doesn't leave a tunnel behind: the request context ends,
//     the dial aborts, and a connection that finished just too late is closed on the spot.
//
// The system-touching parts (dialing WARP, the utun, routes) sit behind the Opener interface so all
// of the above can be tested without root or a network.
package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/feg55/zarp-macos/zarpd/connection"
	"github.com/feg55/zarp-macos/zarpd/ipc"
	"github.com/feg55/zarp-macos/zarpd/warp"
)

// Conn is one live tunnel, as the registry sees it.
type Conn interface {
	// Name is the tunnel interface (utun5).
	Name() string
	// Done is closed when the data plane stops — whether Close was called or the tunnel died on
	// its own.
	Done() <-chan struct{}
	// Err is why the data plane stopped (nil until Done is closed, and for a plain Close).
	Err() error
	// Close attempts every teardown step (routes, DNS, device, session). It joins
	// the work and retains any error across repeated calls. Nil means no step
	// reported a failure; system acceptance still verifies routes/DNS separately.
	Close() error
}

// No private route/configuration detail crosses IPC when teardown is uncertain.
var errCleanupIncomplete = errors.New("network cleanup incomplete; further tunnel starts refused")

func cleanupError() error {
	return &ipc.ConnError{Code: ipc.CodeInternal, Message: errCleanupIncomplete.Error()}
}

// OpenInfo is what an Opener reports about a connection it established.
type OpenInfo struct {
	Endpoint  string // "ip:port" actually dialed
	UtunName  string
	RouteAll  bool     // true: full tunnel; false: test route only
	ConnectMs int      // how long the MASQUE handshake took
	Warnings  []string // non-fatal problems to surface in the app's log
}

// Opener establishes tunnels. The real one dials WARP, creates the utun and installs the routes
// (opener.go); tests substitute a fake.
type Opener interface {
	// Open must honor ctx: when it ends (the requesting client left) the dial is abandoned.
	Open(ctx context.Context, p ipc.OpenParams) (Conn, OpenInfo, error)
}

// Accounts is the WARP account store.
type Accounts interface {
	Has() bool
	Register(ctx context.Context) error
}

// Config assembles a Manager. Opener, Accounts and Measurer are required.
type Config struct {
	Opener   Opener
	Accounts Accounts
	Measurer Measurer
	Logs     *LogRing
	// Startup recovery found unverified network leftovers. Expose status, but
	// never admit another tunnel or advertise idle in this manager lifetime.
	CleanupIncomplete bool

	Version     string
	MeasureHost string // the host measurements target (a Cloudflare address, so trace works)
	// TestLease is how long a non-persistent connection may stay open (default 2 minutes).
	TestLease time.Duration
	// Restart is called, in its own goroutine shortly after the response is sent, by the `restart`
	// method. Production exits non-zero so launchd's KeepAlive{SuccessfulExit:false} relaunches the
	// daemon.
	Restart func()
	Logf    func(format string, args ...any)
	Now     func() time.Time
}

// Manager is the registry plus the method handlers. Create it with NewManager.
type Manager struct {
	cfg Config

	// openSem serializes opens: only one tunnel may exist, and an open that arrives while another
	// is mid-dial waits for it (or for its own request to be cancelled).
	openSem chan struct{}
	regMu   sync.Mutex // serializes registration

	mu            sync.Mutex
	conns         map[string]*entry
	opening       int // admitted opens, including those waiting for openSem
	accountBusy   bool
	stopping      bool
	stop          chan struct{}
	openCancel    context.CancelFunc // current openSem owner's dial only
	cleanupFailed bool               // sticky until this manager ends; idle must never be inferred
	nextSeq       uint64
	lastLoss      *ipc.LossInfo
	closedReasons map[string]closedReason
}

type entry struct {
	id              string
	seq             uint64
	conn            Conn
	params          ipc.OpenParams
	info            OpenInfo
	startedAt       time.Time
	lease           *time.Timer
	closing         bool
	closed          chan struct{} // joined by competing teardown/replacement requests
	closeErr        error
	terminalFailure *ipc.ConnError
}

// NewManager returns a ready Manager.
func NewManager(cfg Config) *Manager {
	if cfg.TestLease <= 0 {
		cfg.TestLease = 2 * time.Minute
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logs == nil {
		cfg.Logs = NewLogRing(1000)
	}
	return &Manager{cfg: cfg, openSem: make(chan struct{}, 1), stop: make(chan struct{}), conns: map[string]*entry{}, closedReasons: map[string]closedReason{}, cleanupFailed: cfg.CleanupIncomplete}
}

// Handle is the ipc.Handler: it dispatches one request.
func (m *Manager) Handle(ctx context.Context, method string, params json.RawMessage) (any, error) {
	switch method {
	case "ping":
		capabilities := m.capabilities()
		return ipc.PingResult{
			Version:              m.cfg.Version,
			Pid:                  os.Getpid(),
			Protocol:             ipc.ProtocolVersion,
			AccountRegistered:    m.cfg.Accounts.Has(),
			AccountSetupVersion:  m.accountSetupVersion(),
			WarpAccountState:     m.accountState(),
			RuntimeCapabilities:  &capabilities,
			ServerRoutingVersion: m.serverRoutingVersion(),
			WarpTLSNameVersion:   1,
			WarpPlusSupported:    func() bool { _, ok := m.cfg.Accounts.(warpAccounts); return ok }(),
		}, nil
	case "status":
		return m.Status(), nil
	case "register":
		return m.register(ctx)
	case "setupWarpAccount":
		return m.setupWarpAccount(ctx, params)
	case "warpAccount":
		return m.warpAccount(ctx, params, false)
	case "warpLicense":
		return m.warpAccount(ctx, params, true)
	case "open":
		return m.open(ctx, params)
	case "openServer":
		return m.openServer(ctx, params)
	case "close":
		return m.closeMethod(params)
	case "measure":
		return m.measure(ctx, params)
	case "logs":
		return m.logs(params)
	case "restart":
		return m.restart()
	default:
		return nil, &ipc.ConnError{Message: fmt.Sprintf("unknown method %q", method), Code: ipc.CodeBadRequest}
	}
}

func decode(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return &ipc.ConnError{Message: "malformed parameters: " + err.Error(), Code: ipc.CodeBadRequest}
	}
	return nil
}

// ---- register

func (m *Manager) register(ctx context.Context) (any, error) {
	m.regMu.Lock()
	defer m.regMu.Unlock()
	if m.cfg.Accounts.Has() {
		return ipc.RegisterResult{AccountRegistered: true}, nil
	}
	ctx, finish, _, err := m.beginAccountOperation(ctx, warp.AccountSetupTimeout, true)
	if err != nil {
		return nil, err
	}
	defer finish()
	m.cfg.Logf("registering a WARP account (the user accepted Cloudflare's terms in Zarp)...")
	if err := m.cfg.Accounts.Register(ctx); err != nil {
		m.cfg.Logf("WARP registration failed")
		return nil, accountSetupError(err)
	}
	m.cfg.Logf("WARP account registered")
	return ipc.RegisterResult{AccountRegistered: m.cfg.Accounts.Has()}, nil
}

// ---- open / close

func (m *Manager) open(ctx context.Context, raw json.RawMessage) (any, error) {
	var p ipc.OpenParams
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if connection.ValidateDocumentJSON(raw, connection.MaxRequestBytes) != nil || decoder.Decode(&p) != nil {
		return nil, &ipc.ConnError{Code: ipc.CodeBadRequest, Message: "invalid WARP open parameters"}
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return m.openParams(ctx, p)
}

func (m *Manager) openParams(ctx context.Context, p ipc.OpenParams) (any, error) {
	if p.Transport == "" {
		p.Transport = "masqueH3"
	}
	if p.Mode != "server" && !m.cfg.Accounts.Has() {
		return nil, &ipc.ConnError{Code: ipc.CodeNoAccount, Message: "no WARP account yet: accept Cloudflare's terms in Zarp to register one"}
	}
	m.mu.Lock()
	if m.cleanupFailed {
		m.mu.Unlock()
		return nil, cleanupError()
	}
	if m.stopping || ctx.Err() != nil {
		m.mu.Unlock()
		return nil, cancelled()
	}
	m.opening++
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.opening--
		m.mu.Unlock()
	}()

	// One open at a time; a second waits for the first to finish — or abort, if its client left.
	select {
	case m.openSem <- struct{}{}:
	case <-ctx.Done():
		return nil, cancelled()
	case <-m.stop:
		return nil, cancelled()
	}
	defer func() { <-m.openSem }()
	// Closing the manager cancels this exact admitted dial, then joins its
	// cleanup through openSem. A queued open cannot revive a stopped manager.
	m.mu.Lock()
	if m.stopping || ctx.Err() != nil {
		m.mu.Unlock()
		return nil, cancelled()
	}
	ctx, cancel := context.WithCancel(ctx)
	m.openCancel = cancel
	m.mu.Unlock()
	defer func() {
		cancel()
		m.mu.Lock()
		m.openCancel = nil
		m.mu.Unlock()
	}()

	// The single-tunnel invariant: anything still open is closed first (see the package comment).
	if err := m.closeAll("superseded by a new connection request"); err != nil {
		return nil, cleanupError()
	}
	if ctx.Err() != nil {
		return nil, cancelled()
	}

	started := m.cfg.Now()
	conn, info, err := m.cfg.Opener.Open(ctx, p)
	if err != nil {
		if errors.Is(err, errCleanupIncomplete) {
			m.mu.Lock()
			m.cleanupFailed = true
			m.mu.Unlock()
			return nil, cleanupError()
		}
		if ctx.Err() != nil && !isTimeoutErr(err) {
			return nil, cancelled()
		}
		return nil, err
	}
	if ctx.Err() != nil {
		// The client left between the dial finishing and now: nobody will ever close this.
		if err := m.closeUnpublished(conn); err != nil {
			return nil, err
		}
		return nil, cancelled()
	}
	if info.ConnectMs <= 0 {
		info.ConnectMs = int(m.cfg.Now().Sub(started).Milliseconds())
	}
	if info.UtunName == "" {
		info.UtunName = conn.Name()
	}

	m.mu.Lock()
	if m.stopping || ctx.Err() != nil {
		m.mu.Unlock()
		if err := m.closeUnpublished(conn); err != nil {
			return nil, err
		}
		return nil, cancelled()
	}
	m.nextSeq++
	e := &entry{
		id: strconv.FormatUint(m.nextSeq, 10), seq: m.nextSeq,
		conn: conn, params: p, info: info, startedAt: started,
	}
	m.conns[e.id] = e
	if p.Persistent {
		m.lastLoss = nil // a fresh tunnel supersedes the report of the last one that died
	}
	if !p.Persistent {
		id := e.id
		e.lease = time.AfterFunc(m.cfg.TestLease, func() { m.closeConn(id, "test connection lease expired (its client never closed it)") })
	}
	m.mu.Unlock()

	go func() {
		<-conn.Done()
		m.onDead(e)
	}()

	m.cfg.Logf("open #%s transport=%s endpoint=%s connectMs=%d dev=%s persistent=%v routeAll=%v",
		e.id, p.Transport, info.Endpoint, info.ConnectMs, info.UtunName, p.Persistent, info.RouteAll)
	for _, w := range info.Warnings {
		m.cfg.Logf("open #%s: warning: %s", e.id, w)
	}
	return ipc.OpenResult{
		ConnectionID: e.id, ConnectMs: info.ConnectMs, Endpoint: info.Endpoint,
		UtunName: info.UtunName, RouteAll: info.RouteAll, Warnings: info.Warnings,
	}, nil
}

func cancelled() error {
	return &ipc.ConnError{Code: ipc.CodeCancelled, Message: "cancelled: the caller went away or a newer request replaced this one"}
}

func isTimeoutErr(err error) bool {
	var ce *ipc.ConnError
	if errors.As(err, &ce) && ce.TimedOut {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded)
}

func (m *Manager) closeUnpublished(conn Conn) error {
	if conn.Close() != nil {
		m.mu.Lock()
		m.cleanupFailed = true
		m.mu.Unlock()
		return cleanupError()
	}
	return nil
}

func (m *Manager) closeMethod(raw json.RawMessage) (any, error) {
	var p ipc.CloseParams
	if err := decode(raw, &p); err != nil {
		return nil, err
	}
	if _, err := m.closeConn(p.ConnectionID, "closed by the app"); err != nil {
		return nil, cleanupError()
	}
	return struct{}{}, nil
}

// closeConn keeps an entry observable until teardown returns. Competing close,
// loss, lease and replacement requests cannot skip or repeat that teardown.
func (m *Manager) closeConn(id, why string) (bool, error) {
	m.mu.Lock()
	e, ok := m.conns[id]
	if !ok {
		m.mu.Unlock()
		return false, nil
	}
	if e.closing {
		done := e.closed
		m.mu.Unlock()
		<-done
		return true, e.closeErr
	}
	e.closing = true
	e.closed = make(chan struct{})
	failure := terminalFailure(e, ipc.CodeConnectionClosed, why)
	e.terminalFailure = &failure
	m.mu.Unlock()
	m.finish(e, why)
	return true, e.closeErr
}

func (m *Manager) finish(e *entry, why string) {
	if e.lease != nil {
		e.lease.Stop()
	}
	err := e.conn.Close()
	m.mu.Lock()
	m.rememberClosedReasonLocked(e)
	if err != nil {
		e.closeErr = errCleanupIncomplete
		m.cleanupFailed = true
	} else if m.conns[e.id] == e {
		delete(m.conns, e.id)
	}
	close(e.closed)
	m.mu.Unlock()
	if err != nil {
		m.cfg.Logf("cleanup incomplete #%s (%s)", e.id, e.info.UtunName)
		return
	}
	m.cfg.Logf("closed #%s (%s): %s", e.id, e.info.UtunName, why)
}

// closeAll closes every live connection.
func (m *Manager) closeAll(why string) error {
	m.mu.Lock()
	all := make([]string, 0, len(m.conns))
	for id := range m.conns {
		all = append(all, id)
	}
	m.mu.Unlock()
	for _, id := range all {
		m.closeConn(id, why)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cleanupFailed {
		return errCleanupIncomplete
	}
	return nil
}

// CloseAll joins teardown before shutdown and reports any unverified cleanup.
// Admission stays closed; this manager cannot be reused after
// shutdown. Cancellation alone is insufficient, so join the in-flight dial too.
func (m *Manager) CloseAll() error {
	m.mu.Lock()
	if !m.stopping {
		m.stopping = true
		close(m.stop)
	}
	cancel := m.openCancel
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	m.openSem <- struct{}{}
	defer func() { <-m.openSem }()
	return m.closeAll("daemon shutting down")
}

// onDead handles a tunnel whose data plane stopped on its own.
func (m *Manager) onDead(e *entry) {
	reason := connectionEndReason(e.conn)
	m.mu.Lock()
	cur, ok := m.conns[e.id]
	if !ok || cur != e || e.closing {
		// Already removed by a close request / supersede: this is just the echo of that.
		m.mu.Unlock()
		return
	}
	e.closing = true
	e.closed = make(chan struct{})
	failure := terminalFailure(e, ipc.CodeConnectionLost, reason)
	e.terminalFailure = &failure
	if e.params.Persistent {
		m.lastLoss = &ipc.LossInfo{
			ConnectionID: e.id, Reason: reason, At: m.cfg.Now().UTC().Format(time.RFC3339),
		}
	}
	m.mu.Unlock()
	m.finish(e, "lost: "+reason)
}

// ---- status

// Status reports the one persistent connection, if any.
func (m *Manager) Status() ipc.StatusResult {
	account := m.cfg.Accounts.Has()
	m.mu.Lock()
	defer m.mu.Unlock()
	capabilities := m.capabilities()
	res := ipc.StatusResult{
		DaemonRunning:       true,
		AccountRegistered:   account,
		NetworkBusy:         m.opening > 0 || m.accountBusy || len(m.conns) > 0 || m.stopping || m.cleanupFailed,
		LastLoss:            m.lastLoss,
		RuntimeCapabilities: &capabilities,
	}
	var newest *entry
	for _, e := range m.conns {
		if !e.closing && e.params.Persistent && (newest == nil || e.seq > newest.seq) {
			newest = e
		}
	}
	if newest == nil {
		return res
	}
	res.Connected = true
	res.ActiveMode = string(connection.Warp)
	if newest.params.Mode == "server" {
		res.ActiveMode = "server"
		res.ServerID = newest.params.Profile.ID()
		res.SourceID = newest.params.SourceID
	}
	res.ConnectionID = newest.id
	res.StrategyID = newest.params.StrategyID
	res.Endpoint = newest.info.Endpoint
	res.Transport = newest.params.Transport
	res.ConnectMs = newest.info.ConnectMs
	res.ConnectStartedAt = newest.startedAt.UTC().Format(time.RFC3339)
	res.UtunName = newest.info.UtunName
	res.RouteAll = newest.info.RouteAll
	// A live tunnel supersedes an old loss report.
	res.LastLoss = nil
	return res
}

// ---- measure

func (m *Manager) measure(ctx context.Context, raw json.RawMessage) (any, error) {
	var p ipc.MeasureParams
	if err := decode(raw, &p); err != nil {
		return nil, err
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	e, err := m.measurementConnection(p.ConnectionID)
	if err != nil {
		return nil, err
	}
	if e.params.Mode == "server" {
		verify := func() error {
			if conn, ok := e.conn.(interface{ VerifyMeasurementPath() error }); ok {
				return conn.VerifyMeasurementPath()
			}
			return nil
		}
		if verify() != nil {
			return ipc.MeasureResult{Kind: "noTraffic", LastError: "server measurement route is unavailable"}, nil
		}
		if measurer, ok := m.cfg.Measurer.(interface {
			MeasureServer(context.Context, string, int) ipc.MeasureResult
		}); ok {
			result := measurer.MeasureServer(ctx, m.cfg.MeasureHost, p.Samples)
			if verify() != nil {
				return ipc.MeasureResult{Kind: "noTraffic", LastError: "server measurement route changed"}, nil
			}
			return m.finishMeasurement(e, result)
		}
		return nil, &ipc.ConnError{Code: ipc.CodeUnsupported, Message: "server traffic measurement is unavailable"}
	}
	return m.finishMeasurement(e, m.cfg.Measurer.Measure(ctx, m.cfg.MeasureHost, p.Samples))
}

// ---- logs / restart

func (m *Manager) logs(raw json.RawMessage) (any, error) {
	var p ipc.LogsParams
	if err := decode(raw, &p); err != nil {
		return nil, err
	}
	lines, next, dropped := m.cfg.Logs.Since(p.Since)
	return ipc.LogsResult{Lines: lines, Next: next, Dropped: dropped}, nil
}

// restart is how the app restarts a root LaunchDaemon that the unprivileged app
// cannot itself start or stop (launchd's own security boundary — no `sudo`/root needed from the
// app's side is the whole point): closes every live connection cleanly, acknowledges the request,
// then — from a separate goroutine, after a short delay so the acknowledgement actually reaches
// the caller before the process disappears — exits with a non-zero status. The LaunchDaemon plist
// has `KeepAlive: {SuccessfulExit: false}`, which restarts on exactly that (an *unsuccessful*
// exit) but deliberately not on a clean `os.Exit(0)`/SIGTERM shutdown, so this is what tells
// launchd "bring it back," as distinct from "stop." Real "stop" only exists via `unregister()`
// (App/Sources/Zarp/ZarpdInstaller.swift) — no in-between, unprivileged, "paused but still
// installed" state exists without root.
func (m *Manager) restart() (any, error) {
	if err := m.CloseAll(); err != nil {
		return nil, cleanupError()
	}
	if m.cfg.Restart != nil {
		go func() {
			time.Sleep(200 * time.Millisecond)
			m.cfg.Restart()
		}()
	}
	return ipc.RestartResult{Acknowledged: true}, nil
}
