package proxy

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestSupervisorRenewalKeepsChildPastOriginalExpiryThenExpires(t *testing.T) {
	s := fakeSupervisor(t)
	limits := Limits{StartupTimeout: 4 * time.Second, Lifetime: 5 * time.Second, StopGrace: 20 * time.Millisecond}
	session, err := s.StartLoopback(context.Background(), testPlan(t, "ignore-term"), limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	original := session.Status().LeaseExpiresAt
	before := time.Now()
	if err := session.RenewLease(); err != nil {
		t.Fatal(err)
	}
	renewed := session.Status().LeaseExpiresAt
	if !renewed.After(original) || renewed.Before(before.Add(limits.Lifetime)) || renewed.After(time.Now().Add(limits.Lifetime)) {
		t.Fatal("renewal did not preserve its bounded duration")
	}
	time.Sleep(time.Until(original.Add(30 * time.Millisecond)))
	if _, ready := session.readyStatus(); !ready {
		t.Fatal("renewed child stopped at its original deadline")
	}
	select {
	case <-session.Done():
	case <-time.After(time.Until(renewed) + time.Second):
		t.Fatal("renewed lease did not eventually expire")
	}
	if session.Status().State != Expired || !session.Status().CleanupOK || session.RenewLease() != (Error{Inactive}) {
		t.Fatal("expired runtime was revived or cleanup unverified")
	}
	assertPrivateClean(t, s)
}

func TestSupervisorRenewalCannotExtendParentDeadline(t *testing.T) {
	s := fakeSupervisor(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	parent, _ := ctx.Deadline()
	session, err := s.StartLoopback(ctx, testPlan(t, "ignore-term"), Limits{StartupTimeout: 4 * time.Second, Lifetime: 15 * time.Second, StopGrace: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	if err := session.RenewLease(); err != nil || !session.Status().LeaseExpiresAt.Equal(parent) {
		t.Fatal("renewal extended the daemon parent's deadline")
	}
	select {
	case <-session.Done():
	case <-time.After(time.Until(parent) + time.Second):
		t.Fatal("parent deadline retained owned child")
	}
	if session.Status().State != Expired || !session.Status().CleanupOK || session.RenewLease() != (Error{Inactive}) {
		t.Fatal("parent expiry did not remain terminal")
	}
	assertPrivateClean(t, s)
}

func TestSupervisorConcurrentRenewalCannotReviveClose(t *testing.T) {
	s := fakeSupervisor(t)
	session, err := s.StartLoopback(context.Background(), testPlan(t, "ignore-term"), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	var callers sync.WaitGroup
	for i := 0; i < 32; i++ {
		callers.Add(1)
		go func() {
			defer callers.Done()
			if err := session.RenewLease(); err != nil && err != (Error{Inactive}) {
				t.Error("unexpected renewal failure")
			}
			if err := session.Close(); err != nil {
				t.Error("concurrent close failed")
			}
		}()
	}
	callers.Wait()
	if session.RenewLease() != (Error{Inactive}) || session.Status().State != Stopped {
		t.Fatal("renewal revived a closed child")
	}
	assertPrivateClean(t, s)
}

func TestRenewalAndAdoptionRefuseExpiredOrExitedBeforeWatcherRuns(t *testing.T) {
	for _, scenario := range []string{"expired", "exited", "cancelled", "stopping"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			child := &ownedChild{done: make(chan struct{}), output: &boundedOutput{}}
			session := &Session{ctx: ctx, child: child, leaseDuration: time.Second, leaseWake: make(chan struct{}, 1),
				status: Status{State: Ready, LeaseExpiresAt: time.Now().Add(time.Second)}}
			switch scenario {
			case "expired":
				session.status.LeaseExpiresAt = time.Now().Add(-time.Second)
			case "exited":
				close(child.done)
			case "cancelled":
				cancel()
			case "stopping":
				session.stopping = true
			}
			if session.RenewLease() != (Error{Inactive}) {
				t.Fatal("terminal condition revived before watcher updated status")
			}
			if _, ready := session.readyStatus(); ready {
				t.Fatal("terminal condition offered for adoption")
			}
		})
	}
}
