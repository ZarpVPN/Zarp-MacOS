package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"

	"github.com/feg55/zarp-macos/zarpd/connection"
)

// RuntimeSnapshot identifies an actual owned run without exposing credentials,
// endpoints, raw configuration or process IDs. It is not a traffic health proof.
type RuntimeSnapshot struct {
	RunID               string
	ServerID            string
	StrategyFingerprint string
	Backend             Status
}

type ownedRuntime struct {
	probe     probeAccess
	probeBusy bool
	probes    sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{}
	snapshot  RuntimeSnapshot
	chain     *Chain
	clean     bool
}

// RuntimeOwner belongs to the daemon, not to a GUI request. A successful startup
// detaches from the request context; a replacement client can adopt its identity.
// Stop/renew require the exact run generation, so stale requests cannot affect a
// newer run. The daemon context and finite lease still stop the owned chain.
// This loopback foundation is not registered with production IPC. It cannot
// adopt arbitrary PIDs, recover after daemon death, or start a system frontend.
type RuntimeOwner struct {
	supervisor runtimeBackend
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
	closed     bool
	run        *ownedRuntime
}

func NewRuntimeOwner(daemonContext context.Context, supervisor runtimeBackend) *RuntimeOwner {
	ctx, cancel := context.WithCancel(daemonContext)
	return &RuntimeOwner{supervisor: supervisor, ctx: ctx, cancel: cancel}
}

// StartLoopback takes exclusive ownership of resource even on refusal. The
// caller must supply a fresh resource, never one from another run. Server ID is
// derived from the validated profile; strategy identity is its configuration
// fingerprint. A second run is refused until the first has verified cleanup.
func (o *RuntimeOwner) StartLoopback(requestContext context.Context, profile connection.Profile, access LoopbackAccess, strategyFingerprint string, limits Limits, resource OwnedResource) (RuntimeSnapshot, error) {
	refuse := func(err error) (RuntimeSnapshot, error) {
		if resource != nil && !closeResource(resource) {
			return RuntimeSnapshot{}, Error{Cleanup}
		}
		return RuntimeSnapshot{}, err
	}
	if o.supervisor == nil || resource == nil || !validFingerprint(strategyFingerprint) {
		return refuse(Error{InvalidPlan})
	}
	if requestContext.Err() != nil {
		return refuse(Error{Cancelled})
	}
	plan, err := PlanFromLoopbackProfile(profile, access)
	if err != nil {
		return refuse(err)
	}
	version, available := o.supervisor.versionFor(plan.Engine)
	if !available {
		return refuse(Error{BinaryUnavailable})
	}
	var generation [16]byte
	if _, err := rand.Read(generation[:]); err != nil {
		return refuse(Error{Startup})
	}
	o.mu.Lock()
	if o.closed || o.ctx.Err() != nil {
		o.mu.Unlock()
		return refuse(Error{Inactive})
	}
	if o.run != nil {
		select {
		case <-o.run.done:
			if !o.run.clean {
				o.mu.Unlock()
				return refuse(Error{Cleanup})
			}
		default:
			o.mu.Unlock()
			return refuse(Error{Busy})
		}
	}
	ctx, cancel := context.WithCancel(o.ctx)
	run := &ownedRuntime{probe: probeAccess{listen: plan.Listen, user: plan.ProbeUser, password: plan.ProbePassword}, ctx: ctx, cancel: cancel, done: make(chan struct{}), snapshot: RuntimeSnapshot{
		RunID: hex.EncodeToString(generation[:]), ServerID: profile.ID(), StrategyFingerprint: strategyFingerprint,
		Backend: Status{Engine: plan.Engine, Version: version, State: Starting},
	}}
	o.run = run
	o.mu.Unlock()

	// Request cancellation applies during startup only. Stop prevents a delayed
	// callback from cancelling the persistent chain after startup is committed.
	stopRequest := context.AfterFunc(requestContext, cancel)
	chain, err := o.supervisor.StartLoopbackChain(ctx, plan, limits, resource)
	detached := stopRequest()
	if err != nil {
		state := Failed
		if err == (Error{Cancelled}) {
			state = Stopped
		}
		o.finish(run, err != (Error{Cleanup}), Status{Engine: plan.Engine, Version: run.snapshot.Backend.Version, State: state})
		return RuntimeSnapshot{}, err
	}
	o.mu.Lock()
	run.chain = chain
	status, ready := chain.engine.readyStatus()
	code := Startup
	if !detached || requestContext.Err() != nil || ctx.Err() != nil || o.closed {
		code = Cancelled
	}
	if code == Cancelled || !ready {
		o.mu.Unlock()
		cancel()
		cleanupErr := chain.Close()
		o.finish(run, cleanupErr == nil, chain.Status())
		if cleanupErr != nil {
			return RuntimeSnapshot{}, cleanupErr
		}
		return RuntimeSnapshot{}, Error{code}
	}
	run.snapshot.Backend = status
	result := run.snapshot
	o.mu.Unlock()
	go func() {
		<-chain.Done()
		err := chain.Close()
		o.finish(run, err == nil, chain.Status())
	}()
	return result, nil
}

func validFingerprint(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (o *RuntimeOwner) finish(run *ownedRuntime, clean bool, status Status) {
	o.mu.Lock()
	run.cancel() // Serialize probe admission with cancellation before joining.
	o.mu.Unlock()
	run.probes.Wait()
	o.mu.Lock()
	defer o.mu.Unlock()
	run.probe = probeAccess{}
	run.clean = clean
	status.CleanupOK = clean
	run.snapshot.Backend = status
	close(run.done)
}

// Snapshot also retains the last terminal result so cleanup failure is visible.
func (o *RuntimeOwner) Snapshot() (RuntimeSnapshot, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.run == nil {
		return RuntimeSnapshot{}, false
	}
	result := o.run.snapshot
	if o.run.chain != nil {
		result.Backend = o.run.chain.Status()
	}
	return result, true
}

// Adopt returns the existing ready run. It does not start, renew or replace it,
// and readiness must not be displayed as verified tunnel traffic.
func (o *RuntimeOwner) Adopt() (RuntimeSnapshot, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	run := o.run
	if o.closed || o.ctx.Err() != nil || run == nil || run.chain == nil || run.ctx.Err() != nil {
		return RuntimeSnapshot{}, Error{Inactive}
	}
	status, ready := run.chain.engine.readyStatus()
	if !ready {
		return RuntimeSnapshot{}, Error{Inactive}
	}
	result := run.snapshot
	result.Backend = status
	return result, nil
}

// RenewLease is a trusted daemon operation. A GUI adoption/status request never
// renews automatically, and this method is not exposed through production IPC.
func (o *RuntimeOwner) RenewLease(runID string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.ctx.Err() != nil || o.run == nil || o.run.snapshot.RunID != runID || o.run.chain == nil {
		return Error{Inactive}
	}
	return o.run.chain.RenewLease()
}

func (o *RuntimeOwner) Stop(runID string) error {
	o.mu.Lock()
	run := o.run
	if run == nil || run.snapshot.RunID != runID {
		o.mu.Unlock()
		return Error{Inactive}
	}
	run.cancel()
	o.mu.Unlock()
	<-run.done
	o.mu.Lock()
	defer o.mu.Unlock()
	if !run.clean {
		return Error{Cleanup}
	}
	return nil
}

// Close cancels startup or the active run, waits for its verified teardown and
// permanently refuses new starts. Concurrent/repeated callers join that work.
func (o *RuntimeOwner) Close() error {
	o.mu.Lock()
	o.closed = true
	o.cancel()
	run := o.run
	o.mu.Unlock()
	if run == nil {
		return nil
	}
	<-run.done
	o.mu.Lock()
	defer o.mu.Unlock()
	if !run.clean {
		return Error{Cleanup}
	}
	return nil
}
