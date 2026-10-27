package proxy

import (
	"context"
	"sync"
	"time"
)

// OwnedResource is a trusted in-process resource created for this run, such as
// its authenticated TCP/UDP outer relay. It is never decoded from IPC.
type OwnedResource interface {
	CloseBounded(context.Context) error
}

type runtimeSession interface {
	Done() <-chan struct{}
	Status() Status
	Close() error
	RenewLease() error
	readyStatus() (Status, bool)
}

type runtimeBackend interface {
	StartLoopbackChain(context.Context, LoopbackPlan, Limits, OwnedResource) (*Chain, error)
	versionFor(Engine) (string, bool)
}

type Chain struct {
	engine    runtimeSession
	cancel    context.CancelFunc
	done      chan struct{}
	mu        sync.Mutex
	cleanupOK bool
}

func (c *Chain) Done() <-chan struct{} { return c.done }
func (c *Chain) Status() Status {
	status := c.engine.Status()
	c.mu.Lock()
	status.CleanupOK = status.CleanupOK && c.cleanupOK
	c.mu.Unlock()
	return status
}
func (c *Chain) Close() error {
	c.cancel()
	<-c.done
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.cleanupOK {
		return Error{Cleanup}
	}
	return nil
}

// RenewLease keeps the engine and its owned outer resource together. It does not
// transfer ownership to a GUI client or restore a chain already being closed.
func (c *Chain) RenewLease() error {
	select {
	case <-c.done:
		return Error{Inactive}
	default:
	}
	return c.engine.RenewLease()
}

// StartLoopbackChain transfers ownership even when startup fails. The approved
// resource must already belong exclusively to this plan/run, never another VPN.
// A child exit, lease expiry or caller cancellation tears down both pieces.
func (s *Supervisor) StartLoopbackChain(ctx context.Context, plan LoopbackPlan, limits Limits, resource OwnedResource) (*Chain, error) {
	return startLoopbackChain(ctx, plan, limits, resource, func(ctx context.Context, plan LoopbackPlan, limits Limits) (runtimeSession, error) {
		return s.StartLoopback(ctx, plan, limits)
	})
}

func startLoopbackChain(ctx context.Context, plan LoopbackPlan, limits Limits, resource OwnedResource,
	start func(context.Context, LoopbackPlan, Limits) (runtimeSession, error)) (*Chain, error) {
	if resource == nil {
		return nil, Error{InvalidPlan}
	}
	runCtx, cancel := context.WithCancel(ctx)
	engine, err := start(runCtx, plan, limits)
	if err != nil {
		cancel()
		if !closeResource(resource) {
			return nil, Error{Cleanup}
		}
		return nil, err
	}
	c := &Chain{engine: engine, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(c.done)
		select {
		case <-runCtx.Done():
		case <-engine.Done():
		}
		cancel()
		// Cancellation closes transport sockets while the child is stopping.
		resourceOK := closeResource(resource)
		engineOK := engine.Close() == nil
		c.mu.Lock()
		c.cleanupOK = resourceOK && engineOK
		c.mu.Unlock()
	}()
	return c, nil
}

func closeResource(resource OwnedResource) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return resource.CloseBounded(ctx) == nil
}
