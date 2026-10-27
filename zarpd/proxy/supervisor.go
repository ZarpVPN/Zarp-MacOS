package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const binaryLimit = 64 << 20
const diagnosticLimit = 32768

type engineSpec struct {
	relative, version, digest, versionPrefix string
}

var pinnedEngines = map[Engine]engineSpec{
	SingBox: {"sing-box-1.13.14/sing-box", "1.13.14", "813d8effd02a19572a8d75aef29fc073101404ca535b2496be86f21827c7684d", "sing-box version 1.13.14\n"},
	Xray:    {"xray-26.9.30/xray", "26.9.30", "118d6c6c8c2fb913c4b2aeb056a58936016b36813c38d9b75653311787c0f93c", "Xray 26.9.30 ("},
}

// Supervisor's inventory root is trusted daemon construction data. Never decode
// it from IPC, profiles or subscriptions. The only binaries are the fixed catalog
// members; they are copied and verified before executing the private snapshot.
// Packaging, signing and production activation remain separate gates.
type Supervisor struct {
	root           string
	specs          map[Engine]engineSpec
	verifySnapshot func(context.Context, string, Engine, time.Duration) error
	parentSession  bool
	serverRuntime  bool
}

// NewParentSessionSupervisor is only for the typed guardian bootstrap inside a
// freshly isolated session. Its parent holds the unreaped guardian leader and
// owns all members/files. This mode is never an imported profile or IPC option.
func NewParentSessionSupervisor(trustedInventoryRoot string) (*Supervisor, error) {
	if !privateSessionLeader() {
		return nil, Error{OwnershipUnsupported}
	}
	s, err := NewSupervisor(trustedInventoryRoot)
	if err == nil {
		s.parentSession = true
	}
	return s, err
}

func (s *Supervisor) versionFor(engine Engine) (string, bool) {
	if s == nil {
		return "", false
	}
	spec, ok := s.specs[engine]
	return spec.version, ok
}

func NewSupervisor(trustedInventoryRoot string) (*Supervisor, error) {
	root, err := filepath.Abs(trustedInventoryRoot)
	if err != nil {
		return nil, Error{BinaryUnavailable}
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, Error{BinaryUnavailable}
	}
	return &Supervisor{root: root, specs: pinnedEngines}, nil
}

type Limits struct {
	StartupTimeout time.Duration
	Lifetime       time.Duration
	StopGrace      time.Duration
}

func DefaultLimits() Limits {
	return Limits{StartupTimeout: 5 * time.Second, Lifetime: time.Minute, StopGrace: 500 * time.Millisecond}
}

func (l Limits) valid() bool {
	return l.StartupTimeout > 0 && l.StartupTimeout <= 15*time.Second &&
		l.Lifetime >= l.StartupTimeout && l.Lifetime <= time.Minute && l.StopGrace > 0 && l.StopGrace <= 2*time.Second
}

type State string

const (
	Starting State = "starting"
	Ready    State = "listener_ready"
	Stopping State = "stopping"
	Exited   State = "exited"
	Failed   State = "failed"
	Stopped  State = "stopped"
	Expired  State = "expired"
)

// Listener readiness is an authenticated SOCKS handshake, not proof of TLS,
// transferred traffic, a system tunnel, or desync effectiveness.
type Status struct {
	Engine         Engine
	Version        string
	State          State
	OutputBytes    int
	OutputCapped   bool
	CleanupOK      bool
	LeaseExpiresAt time.Time
}

type Session struct {
	cancel        context.CancelFunc
	done          chan struct{}
	child         *ownedChild
	dir           string
	grace         time.Duration
	ctx           context.Context
	leaseDuration time.Duration
	leaseWake     chan struct{}
	mu            sync.Mutex
	stopping      bool
	parentSession bool
	status        Status
}

func (s *Session) Done() <-chan struct{} { return s.done }

func (s *Session) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := s.status
	result.OutputBytes, result.OutputCapped = s.child.output.counts()
	return result
}

func (s *Session) readyStatus() (Status, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.readyLocked(time.Now()) {
		return Status{}, false
	}
	result := s.status
	result.OutputBytes, result.OutputCapped = s.child.output.counts()
	return result, true
}

func (s *Session) readyLocked(now time.Time) bool {
	if s.stopping || s.status.State != Ready || s.ctx.Err() != nil || !now.Before(s.status.LeaseExpiresAt) {
		return false
	}
	select {
	case <-s.child.done:
		return false
	default:
		return s.child.active()
	}
}

// Close is idempotent and stops only the process owned by this exact Start call.
func (s *Session) Close() error {
	s.mu.Lock()
	s.stopping = true
	if s.status.State == Starting || s.status.State == Ready {
		s.status.State = Stopping
	}
	s.cancel()
	s.mu.Unlock()
	<-s.done
	if !s.Status().CleanupOK {
		return Error{Cleanup}
	}
	return nil
}

// RenewLease refreshes the original, bounded lease. Only the daemon owner may
// call it after its health/policy checks; it is not an IPC heartbeat. It cannot
// revive an expired, cancelled, stopping or exited child, or extend a parent's
// deadline. Without renewal the existing finite-lifetime behavior is unchanged.
func (s *Session) RenewLease() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if !s.readyLocked(now) {
		return Error{Inactive}
	}
	s.status.LeaseExpiresAt = leaseDeadline(now, s.leaseDuration, s.ctx)
	select {
	case s.leaseWake <- struct{}{}:
	default:
	}
	return nil
}

func leaseDeadline(now time.Time, duration time.Duration, ctx context.Context) time.Time {
	deadline := now.Add(duration)
	if parent, ok := ctx.Deadline(); ok && parent.Before(deadline) {
		deadline = parent
	}
	return deadline
}

func (s *Session) supervise(ctx context.Context) {
	defer close(s.done)
	defer s.cancel()
	state := Exited
	clean := true
	timer := time.NewTimer(0)
	defer timer.Stop()
watch:
	for {
		s.mu.Lock()
		remaining := time.Until(s.status.LeaseExpiresAt)
		if remaining <= 0 {
			s.stopping = true
			s.status.State = Stopping
			s.mu.Unlock()
			state = Expired
			clean = s.child.stop(s.grace)
			break
		}
		s.mu.Unlock()
		timer.Reset(remaining)
		select {
		case <-s.child.done:
			clean = s.child.clean
			if s.child.err != nil {
				state = Failed
			}
			break watch
		case <-ctx.Done():
			state = Stopped
			if ctx.Err() == context.DeadlineExceeded {
				state = Expired
			}
			s.mu.Lock()
			s.stopping = true
			s.status.State = Stopping
			s.mu.Unlock()
			clean = s.child.stop(s.grace)
			break watch
		case <-timer.C:
			// Recheck under the same lock as renewal before declaring expiry.
		case <-s.leaseWake:
		}
	}
	s.mu.Lock()
	s.stopping = true
	if s.status.State == Starting || s.status.State == Ready {
		s.status.State = Stopping
	}
	s.mu.Unlock()
	if clean && !s.parentSession {
		clean = os.RemoveAll(s.dir) == nil
	}
	s.mu.Lock()
	s.status.State, s.status.CleanupOK = state, clean && !s.parentSession
	s.mu.Unlock()
}

// StartLoopback compiles a restricted plan. It cannot enable a system tunnel or
// receive arbitrary configuration/argv. Production IPC does not call it yet.
func (s *Supervisor) StartLoopback(ctx context.Context, plan LoopbackPlan, limits Limits) (result *Session, returnedError error) {
	data, err := plan.compile()
	if err != nil {
		return nil, err
	}
	return s.startPrepared(ctx, plan, data, limits)
}

func (s *Supervisor) startPrepared(ctx context.Context, plan LoopbackPlan, data []byte, limits Limits) (result *Session, returnedError error) {
	if !childOwnershipSupported() {
		return nil, Error{OwnershipUnsupported}
	}
	if s.parentSession {
		ctx = context.WithValue(ctx, parentSessionKey{}, true)
	}
	if !limits.valid() {
		return nil, Error{InvalidLimits}
	}
	started := time.Now()
	leaseExpiresAt := leaseDeadline(started, limits.Lifetime, ctx)
	runCtx, cancel := context.WithCancel(ctx)
	// Internal timer cleanup after child exit must not look like caller cancellation.
	cancellationRequested := func() bool {
		return ctx.Err() != nil || !time.Now().Before(leaseExpiresAt)
	}
	startupCtx, startupCancel := context.WithDeadline(runCtx, started.Add(limits.StartupTimeout))
	defer startupCancel()
	dir, err := os.MkdirTemp("", "zarp-engine-")
	if err != nil {
		cancel()
		return nil, Error{Startup}
	}
	transferred := false
	defer func() {
		if !transferred {
			cancel()
			// Retain private resources if stopping an owned child could not be verified.
			if returnedError != (Error{Cleanup}) && os.RemoveAll(dir) != nil {
				returnedError = Error{Cleanup}
			}
		}
	}()
	spec, ok := s.specs[plan.Engine]
	if !ok {
		return nil, Error{BinaryUnavailable}
	}
	binary, err := s.snapshot(startupCtx, spec, dir)
	if err != nil {
		return nil, err
	}
	if s.verifySnapshot != nil {
		if err := s.verifySnapshot(startupCtx, binary, plan.Engine, limits.StopGrace); err != nil {
			return nil, err
		}
	}
	config := filepath.Join(dir, "config.json")
	if err := os.WriteFile(config, data, 0600); err != nil {
		return nil, Error{Startup}
	}
	versionOutput := &boundedOutput{retain: true}
	if err := runProbe(startupCtx, binary, dir, []string{"version"}, versionOutput, limits.StopGrace); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(versionOutput.text(), spec.versionPrefix) {
		return nil, Error{VersionMismatch}
	}
	checkArgs, runArgs := []string{"check", "-c", config}, []string{"run", "-c", config}
	if plan.Engine == Xray {
		checkArgs, runArgs = []string{"run", "-test", "-config", config}, []string{"run", "-config", config}
	}
	if err := runProbe(startupCtx, binary, dir, checkArgs, &boundedOutput{}, limits.StopGrace); err != nil {
		return nil, err
	}
	if startupCtx.Err() != nil {
		return nil, Error{Cancelled}
	}
	child, err := startScopedChild(startupCtx, binary, dir, runArgs, &boundedOutput{})
	if err != nil {
		return nil, Error{Startup}
	}
	session := &Session{cancel: cancel, done: make(chan struct{}), child: child, dir: dir, grace: limits.StopGrace,
		parentSession: s.parentSession,
		ctx:           runCtx, leaseDuration: limits.Lifetime, leaseWake: make(chan struct{}, 1),
		status: Status{Engine: plan.Engine, Version: spec.version, State: Starting, LeaseExpiresAt: leaseExpiresAt}}
	transferred = true
	go session.supervise(runCtx)
	for {
		select {
		case <-session.done:
			if !session.Status().CleanupOK {
				return nil, Error{Cleanup}
			}
			if cancellationRequested() {
				return nil, Error{Cancelled}
			}
			return nil, Error{Startup}
		default:
		}
		if startupCtx.Err() != nil {
			code := Readiness
			if cancellationRequested() {
				code = Cancelled
			}
			if err := session.Close(); err != nil {
				return nil, err
			}
			if state := session.Status().State; code == Readiness && (state == Failed || state == Exited) {
				code = Startup
			}
			return nil, Error{code}
		}
		if authenticateListener(startupCtx, plan) {
			session.mu.Lock()
			if session.status.State != Starting || session.stopping || runCtx.Err() != nil || !time.Now().Before(leaseExpiresAt) {
				code := Startup
				if cancellationRequested() {
					code = Cancelled
				}
				session.mu.Unlock()
				if err := session.Close(); err != nil {
					return nil, err
				}
				return nil, Error{code}
			}
			session.status.State = Ready
			session.mu.Unlock()
			if s.serverRuntime {
				_ = os.Remove(config)
			}
			return session, nil
		}
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-timer.C:
		case <-startupCtx.Done():
			timer.Stop()
		case <-session.done:
			timer.Stop()
		}
	}
}

func (s *Supervisor) snapshot(ctx context.Context, spec engineSpec, dir string) (string, error) {
	source := filepath.Join(s.root, spec.relative)
	resolved, err := filepath.EvalSymlinks(source)
	if err != nil || resolved != source {
		return "", Error{BinaryUnavailable}
	}
	fd, err := unix.Open(source, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", Error{BinaryUnavailable}
	}
	input := os.NewFile(uintptr(fd), "pinned-engine")
	defer input.Close()
	info, err := input.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0111 == 0 || info.Size() <= 0 || info.Size() > binaryLimit {
		return "", Error{BinaryUnavailable}
	}
	path := filepath.Join(dir, "engine")
	output, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", Error{Startup}
	}
	defer output.Close()
	digest := sha256.New()
	reader := io.LimitReader(input, binaryLimit+1)
	buffer := make([]byte, 32768)
	var total int
	for {
		if ctx.Err() != nil {
			return "", Error{Cancelled}
		}
		n, err := reader.Read(buffer)
		if n > 0 {
			total += n
			if total > binaryLimit {
				return "", Error{BinaryIntegrity}
			}
			if _, werr := output.Write(buffer[:n]); werr != nil {
				return "", Error{Startup}
			}
			_, _ = digest.Write(buffer[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", Error{BinaryUnavailable}
		}
	}
	if hex.EncodeToString(digest.Sum(nil)) != spec.digest {
		return "", Error{BinaryIntegrity}
	}
	if err := output.Chmod(0500); err != nil {
		return "", Error{Startup}
	}
	if err := output.Close(); err != nil {
		return "", Error{Startup}
	}
	return path, nil
}

// Outputs from config validation and runtime are counted and discarded. Only
// the bounded version probe retains bytes, privately, to check its prefix.
type boundedOutput struct {
	mu     sync.Mutex
	data   bytes.Buffer
	retain bool
	bytes  int
	capped bool
}

func (w *boundedOutput) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := len(p)
	remaining := diagnosticLimit - w.bytes
	if n > remaining {
		w.capped = true
		p = p[:remaining]
	}
	w.bytes += len(p)
	if w.retain {
		_, _ = w.data.Write(p)
	}
	return n, nil
}

func (w *boundedOutput) text() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.data.String()
}
func (w *boundedOutput) counts() (int, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.bytes, w.capped
}

func runProbe(ctx context.Context, binary, dir string, args []string, output *boundedOutput, grace time.Duration) error {
	if ctx.Err() != nil {
		return Error{Cancelled}
	}
	c, err := startScopedChild(ctx, binary, dir, args, output)
	if err != nil {
		return Error{Startup}
	}
	select {
	case <-c.done:
		if !c.clean {
			return Error{Cleanup}
		}
		if c.err != nil {
			return Error{Configuration}
		}
		return nil
	case <-ctx.Done():
		if !c.stop(grace) {
			return Error{Cleanup}
		}
		return Error{Cancelled}
	}
}

func authenticateListener(ctx context.Context, p LoopbackPlan) bool {
	conn, err := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(ctx, "tcp", p.Listen.String())
	if err != nil {
		return false
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := conn.Write([]byte{5, 1, 2}); err != nil {
		return false
	}
	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil || reply != [2]byte{5, 2} {
		return false
	}
	auth := append([]byte{1, byte(len(p.ProbeUser))}, p.ProbeUser...)
	auth = append(auth, byte(len(p.ProbePassword)))
	auth = append(auth, p.ProbePassword...)
	if _, err := conn.Write(auth); err != nil {
		return false
	}
	_, err = io.ReadFull(conn, reply[:])
	return err == nil && reply == [2]byte{1, 0}
}
