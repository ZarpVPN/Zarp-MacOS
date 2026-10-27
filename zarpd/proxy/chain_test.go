package proxy

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeOwnedResource struct {
	closed  atomic.Int32
	failure bool
}

func (r *fakeOwnedResource) CloseBounded(ctx context.Context) error {
	r.closed.Add(1)
	if r.failure {
		return errors.New("private-resource-close-error")
	}
	return nil
}

func TestChainTransfersResourceOwnershipOnStartupFailure(t *testing.T) {
	for _, mode := range []string{"check-fail", "exit"} {
		t.Run(mode, func(t *testing.T) {
			s := fakeSupervisor(t)
			resource := &fakeOwnedResource{}
			_, err := s.StartLoopbackChain(context.Background(), testPlan(t, mode), DefaultLimits(), resource)
			if err == nil || resource.closed.Load() != 1 {
				t.Fatal("failed startup retained owned resource")
			}
			assertPrivateClean(t, s)
		})
	}
}

func TestChainCancellationAndLeaseCloseResourceExactlyOnce(t *testing.T) {
	for _, expire := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "lease"}[expire], func(t *testing.T) {
			s := fakeSupervisor(t)
			resource := &fakeOwnedResource{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			chain, err := s.StartLoopbackChain(ctx, testPlan(t, "ignore-term"), Limits{StartupTimeout: 4 * time.Second, Lifetime: 5 * time.Second, StopGrace: 20 * time.Millisecond}, resource)
			if err != nil {
				t.Fatal(err)
			}
			if expire {
				select {
				case <-chain.Done():
				case <-time.After(6 * time.Second):
					_ = chain.Close()
					t.Fatal("lease retained chain")
				}
			} else {
				cancel()
			}
			var callers sync.WaitGroup
			for i := 0; i < 8; i++ {
				callers.Add(1)
				go func() {
					defer callers.Done()
					if err := chain.Close(); err != nil {
						t.Error("chain close failed")
					}
				}()
			}
			callers.Wait()
			if resource.closed.Load() != 1 || !chain.Status().CleanupOK {
				t.Fatal("owned resource duplicated or chain cleanup not verified")
			}
			if expire && chain.Status().State != Expired {
				t.Fatal("lease state lost")
			}
			assertPrivateClean(t, s)
		})
	}
}

func TestChainFailedResourceCleanupIsNotSuccessfulStatus(t *testing.T) {
	s := fakeSupervisor(t)
	resource := &fakeOwnedResource{failure: true}
	chain, err := s.StartLoopbackChain(context.Background(), testPlan(t, "normal"), DefaultLimits(), resource)
	if err != nil {
		t.Fatal(err)
	}
	if err := chain.Close(); err != (Error{Cleanup}) || chain.Status().CleanupOK {
		t.Fatal("failed resource cleanup reported success")
	}
	assertPrivateClean(t, s)
	resource = &fakeOwnedResource{failure: true}
	if _, err := s.StartLoopbackChain(context.Background(), testPlan(t, "check-fail"), DefaultLimits(), resource); err != (Error{Cleanup}) {
		t.Fatal("partial startup resource cleanup failure was hidden")
	}
}
