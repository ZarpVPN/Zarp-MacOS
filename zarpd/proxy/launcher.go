package proxy

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/feg55/zarp-macos/zarpd/connection"
	"golang.org/x/sys/unix"
)

// GuardianLauncher is a trusted construction boundary. Its fixed
// helper is hash-verified into a private snapshot before execution. Neither
// paths nor executable policy can be supplied by profiles or control messages.
// Development, signed-release and product policies have separate constructors.
// Only the product constructor accepts typed server plans. It owns no system
// interface or routes; those remain in the daemon.
type GuardianLauncher struct {
	program      *Supervisor
	helper       engineSpec
	inventory    *Supervisor
	release      bool
	production   bool
	verifyHelper func(context.Context, string, time.Duration) error
}

func NewLoopbackGuardianLauncher(trustedProgramDirectory, expectedProgramDigest, trustedInventoryRoot string) (*GuardianLauncher, error) {
	if !validFingerprint(expectedProgramDigest) {
		return nil, Error{InvalidInventory}
	}
	program, err := NewSupervisor(trustedProgramDirectory)
	if err != nil {
		return nil, err
	}
	inventory, err := NewSupervisor(trustedInventoryRoot)
	if err != nil {
		return nil, err
	}
	return &GuardianLauncher{program: program, helper: engineSpec{relative: "parity-backend-guardian", digest: expectedProgramDigest}, inventory: inventory}, nil
}

func (g *GuardianLauncher) versionFor(engine Engine) (string, bool) {
	if g == nil {
		return "", false
	}
	return g.inventory.versionFor(engine)
}

func (g *GuardianLauncher) StartLoopbackChain(ctx context.Context, plan LoopbackPlan, limits Limits, resource OwnedResource) (*Chain, error) {
	return startLoopbackChain(ctx, plan, limits, resource, func(ctx context.Context, plan LoopbackPlan, limits Limits) (runtimeSession, error) {
		return g.StartLoopback(ctx, plan, limits)
	})
}

// GuardedSession owns the anonymous pipes, private files and reserved guardian
// leader. The guardian and its ordinary engine descendants share the newly
// created session/group. Even a guardian SIGKILL cannot release that leader's
// numeric identity until the parent verifies group/session teardown and reaps.
// A child that creates another session is outside this ownership proof.
type GuardedSession struct {
	ctx          context.Context
	cancel       context.CancelFunc
	done         chan struct{}
	ready        chan struct{}
	renewed      chan struct{}
	child        *ownedChild
	dir          string
	limits       Limits
	control      *os.File
	controlFD    int
	writeMu      sync.Mutex
	actionMu     sync.Mutex
	mu           sync.Mutex
	status       Status
	failure      Code
	stopping     bool
	renewPending bool
}

func (s *GuardedSession) Done() <-chan struct{} { return s.done }
func (s *GuardedSession) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}
func (s *GuardedSession) readyLocked() bool {
	if s.stopping || s.ctx.Err() != nil || s.status.State != Ready || !time.Now().Before(s.status.LeaseExpiresAt) {
		return false
	}
	select {
	case <-s.child.done:
		return false
	default:
		return s.child.active()
	}
}
func (s *GuardedSession) readyStatus() (Status, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status, s.readyLocked()
}
func (s *GuardedSession) Close() error {
	s.mu.Lock()
	s.stopping = true
	if s.status.State == Ready || s.status.State == Starting {
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

// Renewal returns success only after a bounded, validated guardian acknowledgement.
// A queued write alone cannot extend the local lease or revive an inactive run.
func (s *GuardedSession) RenewLease() error {
	s.actionMu.Lock()
	defer s.actionMu.Unlock()
	s.mu.Lock()
	ready := s.readyLocked()
	if ready {
		s.renewPending = true
	}
	s.mu.Unlock()
	if !ready {
		return Error{Inactive}
	}
	select {
	case <-s.renewed:
	default:
	}
	data, _ := json.Marshal(guardianAction{Version: guardianVersion, Action: "renew"})
	s.writeMu.Lock()
	written := s.control != nil && writeGuardianFrame(s.controlFD, data)
	s.writeMu.Unlock()
	if !written {
		s.cancel()
		return Error{ControlLost}
	}
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-s.renewed:
		_, ready = s.readyStatus()
		if ready {
			return nil
		}
		return Error{Inactive}
	case <-s.done:
		return Error{Inactive}
	case <-s.ctx.Done():
		return Error{Inactive}
	case <-timer.C:
		s.cancel()
		return Error{ControlLost}
	}
}

func (s *GuardedSession) closeControl() {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.control != nil {
		_ = s.control.Close()
		s.control = nil
	}
}

func (g *GuardianLauncher) StartLoopback(ctx context.Context, plan LoopbackPlan, limits Limits) (result *GuardedSession, returnedError error) {
	return g.startGuardian(ctx, plan, nil, limits)
}

func NewServerGuardianLauncher(programDirectory, expectedDigest, inventoryRoot string) (*GuardianLauncher, error) {
	g, err := NewLoopbackGuardianLauncher(programDirectory, expectedDigest, inventoryRoot)
	if err == nil {
		g.helper.relative = "zarp-backend-guardian"
		g.production = true
	}
	return g, err
}

func (g *GuardianLauncher) StartServer(ctx context.Context, plan ServerPlan, limits Limits) (*GuardedSession, error) {
	if g == nil || !g.production {
		return nil, Error{InvalidPlan}
	}
	if err := plan.validate(); err != nil {
		return nil, err
	}
	return g.startGuardian(ctx, plan.readiness(), &plan, limits)
}

func (g *GuardianLauncher) startGuardian(ctx context.Context, plan LoopbackPlan, server *ServerPlan, limits Limits) (result *GuardedSession, returnedError error) {
	version, available := g.versionFor(plan.Engine)
	if !available {
		return nil, Error{BinaryUnavailable}
	}
	if !childOwnershipSupported() {
		return nil, Error{OwnershipUnsupported}
	}
	if !limits.valid() {
		return nil, Error{InvalidLimits}
	}
	if server == nil {
		if g.production {
			return nil, Error{InvalidPlan}
		}
		if err := plan.validate(); err != nil {
			return nil, err
		}
	}
	if ctx.Err() != nil {
		return nil, Error{Cancelled}
	}
	bounded, cancelBounded := context.WithCancel(ctx)
	if !g.production {
		cancelBounded()
		bounded, cancelBounded = context.WithTimeout(ctx, guardianLifetime)
	}
	runCtx, cancelRun := context.WithCancel(bounded)
	cancel := func() { cancelRun(); cancelBounded() }
	startup, cancelStartup := context.WithTimeout(runCtx, limits.StartupTimeout)
	defer cancelStartup()
	dir, err := os.MkdirTemp("", "zarp-guardian-")
	if err != nil {
		cancel()
		return nil, Error{Startup}
	}
	transferred := false
	defer func() {
		if !transferred {
			cancel()
			if os.RemoveAll(dir) != nil {
				returnedError = Error{Cleanup}
			}
		}
	}()
	binary, err := g.program.snapshot(startup, g.helper, dir)
	if err != nil {
		return nil, err
	}
	if g.verifyHelper != nil {
		if err := g.verifyHelper(startup, binary, limits.StopGrace); err != nil {
			return nil, err
		}
	}
	argument := "--owned-session"
	if g.release {
		argument = "--release-session"
	}
	if g.production {
		argument = "--server-session"
	}
	controlRead, controlWrite, err := os.Pipe()
	if err != nil {
		return nil, Error{Startup}
	}
	defer controlRead.Close()
	reportRead, reportWrite, err := os.Pipe()
	if err != nil {
		_ = controlWrite.Close()
		return nil, Error{Startup}
	}
	defer reportWrite.Close()
	controlFD, reportFD := int(controlWrite.Fd()), int(reportRead.Fd())
	if !prepareGuardianPipe(controlFD, unix.O_WRONLY) || !prepareGuardianPipe(reportFD, unix.O_RDONLY) {
		_ = controlWrite.Close()
		_ = reportRead.Close()
		return nil, Error{InvalidControl}
	}
	child, err := startChildConstructed(binary, g.inventory.root, dir, []string{argument}, &boundedOutput{}, []*os.File{controlRead, reportWrite}, true)
	if err != nil {
		_ = controlWrite.Close()
		_ = reportRead.Close()
		return nil, Error{Startup}
	}
	_ = controlRead.Close()
	_ = reportWrite.Close()
	s := &GuardedSession{ctx: runCtx, cancel: cancel, done: make(chan struct{}), ready: make(chan struct{}), renewed: make(chan struct{}, 1),
		child: child, dir: dir, limits: limits, control: controlWrite, controlFD: controlFD,
		status: Status{Engine: plan.Engine, Version: version, State: Starting, LeaseExpiresAt: leaseDeadline(time.Now(), limits.Lifetime, runCtx)}}
	transferred = true
	go s.supervise(reportRead, reportFD)
	data, _ := json.Marshal(GuardianStart{Version: guardianVersion, Plan: plan, Server: server, Limits: limits, Ownership: "parent-session"})
	s.writeMu.Lock()
	written := s.control != nil && len(data) <= guardianFrameLimit && writeGuardianFrame(controlFD, data)
	s.writeMu.Unlock()
	if written {
		select {
		case <-s.ready:
			if _, ready := s.readyStatus(); ready && authenticateListener(startup, plan) {
				if _, ready := s.readyStatus(); ready && startup.Err() == nil {
					return s, nil
				}
			}
		case <-s.done:
		case <-startup.Done():
		}
	}
	if err := s.Close(); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, Error{Cancelled}
	}
	s.mu.Lock()
	code := s.failure
	s.mu.Unlock()
	if code == "" {
		code = Readiness
	}
	return nil, Error{code}
}

func (s *GuardedSession) supervise(reader *os.File, fd int) {
	defer close(s.done)
	defer s.cancel()
	readCtx, stopReader := context.WithCancel(context.Background())
	reports := make(chan GuardianReport, 4)
	readerDone := make(chan struct{})
	engine, version := s.status.Engine, s.status.Version
	go func() {
		defer close(readerDone)
		defer close(reports)
		for count := 0; count < 4098; count++ {
			data, err := readGuardianFrame(readCtx, fd, guardianFrameLimit)
			var report GuardianReport
			if err != nil || decodeGuardianReport(data, &report, engine, version) != nil {
				return
			}
			select {
			case reports <- report:
			case <-readCtx.Done():
				return
			}
		}
	}()
	state := Failed
	readySeen := false
	timer := time.NewTimer(time.Until(s.status.LeaseExpiresAt))
	defer timer.Stop()
watch:
	for {
		select {
		case report, ok := <-reports:
			if !ok {
				s.mu.Lock()
				s.failure = ControlLost
				s.mu.Unlock()
				break watch
			}
			s.mu.Lock()
			deadline := leaseDeadline(report.Status.LeaseExpiresAt, 0, s.ctx)
			validLease := deadline.After(time.Now()) && deadline.Before(time.Now().Add(s.limits.Lifetime+time.Second))
			valid := true
			switch report.Phase {
			case "ready":
				valid = validLease && !readySeen && s.status.State == Starting && s.ctx.Err() == nil
				if valid {
					readySeen = true
					s.status = report.Status
					s.status.LeaseExpiresAt = deadline
					close(s.ready)
				}
			case "renewed":
				valid = validLease && readySeen && s.renewPending && s.readyLocked() && report.Code == ""
				if valid {
					s.status = report.Status
					s.status.LeaseExpiresAt = deadline
					s.renewPending = false
					select {
					case s.renewed <- struct{}{}:
					default:
					}
				}
			case "final":
				s.failure = report.Code
				state = report.Status.State
				s.status.OutputBytes, s.status.OutputCapped = report.Status.OutputBytes, report.Status.OutputCapped
				s.mu.Unlock()
				break watch
			}
			if !valid {
				s.failure = InvalidControl
				s.mu.Unlock()
				break watch
			}
			timer.Reset(time.Until(s.status.LeaseExpiresAt))
			s.mu.Unlock()
		case <-s.child.done:
			s.mu.Lock()
			s.failure = ControlLost
			s.mu.Unlock()
			break watch
		case <-s.ctx.Done():
			state = Stopped
			if s.ctx.Err() == context.DeadlineExceeded {
				state = Expired
			}
			break watch
		case <-timer.C:
			state = Expired
			break watch
		}
	}
	s.mu.Lock()
	s.stopping = true
	s.status.State = Stopping
	s.mu.Unlock()
	s.closeControl()
	// Give EOF a bounded chance to perform cooperative direct-child cleanup,
	// then enforce the same reserved group's TERM/KILL fallback.
	select {
	case <-s.child.done:
	case <-time.After(s.limits.StopGrace + 250*time.Millisecond):
	}
	clean := s.child.stop(s.limits.StopGrace)
	stopReader()
	<-readerDone // Join native reads before closing/reusing their descriptor.
	_ = reader.Close()
	if clean {
		clean = os.RemoveAll(s.dir) == nil
	}
	s.mu.Lock()
	s.status.State, s.status.CleanupOK = state, clean
	if !clean {
		s.failure = Cleanup
		s.status.State = Failed
	}
	s.mu.Unlock()
}

func decodeGuardianReport(data []byte, report *GuardianReport, engine Engine, version string) error {
	if connection.ValidateDocumentJSON(data, guardianFrameLimit) != nil {
		return Error{InvalidControl}
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || len(fields) < 3 || len(fields) > 5 {
		return Error{InvalidControl}
	}
	for key := range fields {
		if key != "version" && key != "phase" && key != "code" && key != "status" && key != "directChildStopped" {
			return Error{InvalidControl}
		}
	}
	if !exactGuardianObject(fields["status"], "Engine", "Version", "State", "OutputBytes", "OutputCapped", "CleanupOK", "LeaseExpiresAt") ||
		json.Unmarshal(data, report) != nil || report.Version != guardianVersion || report.Status.OutputBytes < 0 || report.Status.OutputBytes > diagnosticLimit {
		return Error{InvalidControl}
	}
	if report.Status.Engine != engine || report.Status.Version != version && !(report.Phase == "final" && report.Status.Version == "" && report.Status.State == Failed) {
		return Error{InvalidControl}
	}
	switch report.Code {
	case "", InvalidPlan, InvalidLimits, BinaryUnavailable, BinaryIntegrity, BinarySignature, InvalidInventory, VersionMismatch,
		Configuration, Startup, Readiness, Cancelled, Cleanup, Inactive, InvalidControl, ControlLost, OwnershipUnsupported:
	default:
		return Error{InvalidControl}
	}
	switch report.Phase {
	case "ready", "renewed":
		if report.Status.State != Ready || report.DirectChildStopped || report.Status.CleanupOK || report.Status.LeaseExpiresAt.IsZero() || report.Phase == "ready" && report.Code != "" {
			return Error{InvalidControl}
		}
	case "final":
		if report.Status.State != Stopped && report.Status.State != Expired && report.Status.State != Exited && report.Status.State != Failed {
			return Error{InvalidControl}
		}
	default:
		return Error{InvalidControl}
	}
	return nil
}
