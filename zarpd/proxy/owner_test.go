package proxy

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/feg55/zarp-macos/zarpd/connection"
)

func ownerInputs(t *testing.T, mode string) (connection.Profile, LoopbackAccess) {
	t.Helper()
	p := testPlan(t, mode)
	name := p.ServerName
	profile := connection.Profile{Label: "Test server", Host: p.Target.Addr().String(), Port: int(p.Target.Port()),
		Protocol: "trojan", Credential: connection.Credential{Kind: "password", Value: mode},
		Transport: "tcp", Security: "tls", ServerName: &name, ALPN: []string{}, Flow: "none"}
	access := LoopbackAccess{Target: p.Target, Relay: p.Relay, Listen: p.Listen, Pin: p.Pin,
		RelayUser: p.RelayUser, RelayPassword: p.RelayPassword, ProbeUser: p.ProbeUser, ProbePassword: p.ProbePassword}
	return profile, access
}

func ownerLimits() Limits {
	return Limits{StartupTimeout: 4 * time.Second, Lifetime: 15 * time.Second, StopGrace: 20 * time.Millisecond}
}

func waitOwnerListener(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("controlled startup listener was not observed")
}

func TestOwnerAdoptsSameChildAfterRequestClientDisappears(t *testing.T) {
	s := fakeSupervisor(t)
	o := NewRuntimeOwner(context.Background(), s)
	t.Cleanup(func() { _ = o.Close() })
	request, disappear := context.WithCancel(context.Background())
	defer disappear()
	profile, access := ownerInputs(t, "private-server-credential")
	resource := &fakeOwnedResource{}
	started, err := o.StartLoopback(request, profile, access, strings.Repeat("a", 64), ownerLimits(), resource)
	if err != nil {
		t.Fatal(err)
	}
	child := o.run.chain.engine.(*Session).child
	disappear()
	// Allow any erroneously retained request callback to run before adopting.
	time.Sleep(100 * time.Millisecond)
	adopted, err := o.Adopt()
	if err != nil || adopted.RunID != started.RunID || adopted.ServerID != profile.ID() || adopted.StrategyFingerprint != started.StrategyFingerprint || o.run.chain.engine.(*Session).child != child {
		t.Fatal("client disappearance replaced or cancelled the owned run")
	}
	plan, err := PlanFromLoopbackProfile(profile, access)
	if err != nil || !authenticateListener(context.Background(), plan) || resource.closed.Load() != 0 {
		t.Fatal("adopted child is not the original authenticated listener")
	}
	adopted.RunID = "modified-copy"
	current, _ := o.Adopt()
	if current.RunID != started.RunID {
		t.Fatal("adoption returned mutable owner state")
	}
	raw, _ := json.Marshal(current)
	for _, secret := range []string{profile.Credential.Value, access.ProbePassword, access.RelayPassword, profile.Host, *profile.ServerName} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("runtime snapshot disclosed profile/access data")
		}
	}
	busyResource := &fakeOwnedResource{}
	if _, err := o.StartLoopback(context.Background(), profile, access, strings.Repeat("a", 64), ownerLimits(), busyResource); err != (Error{Busy}) || busyResource.closed.Load() != 1 || resource.closed.Load() != 0 {
		t.Fatal("second startup disturbed the active chain or retained new resources")
	}
	if err := o.Stop(started.RunID); err != nil || resource.closed.Load() != 1 {
		t.Fatal("adopted run did not close exactly once")
	}
	assertPrivateClean(t, s)
}

func TestOwnerStaleGenerationCannotStopOrRenewReplacement(t *testing.T) {
	s := fakeSupervisor(t)
	o := NewRuntimeOwner(context.Background(), s)
	t.Cleanup(func() { _ = o.Close() })
	profile, access := ownerInputs(t, "ignore-term")
	firstResource := &fakeOwnedResource{}
	first, err := o.StartLoopback(context.Background(), profile, access, strings.Repeat("b", 64), ownerLimits(), firstResource)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Stop(first.RunID); err != nil {
		t.Fatal(err)
	}
	profile, access = ownerInputs(t, "ignore-term")
	profile.Label = "Renamed server"
	secondResource := &fakeOwnedResource{}
	second, err := o.StartLoopback(context.Background(), profile, access, strings.Repeat("b", 64), ownerLimits(), secondResource)
	if err != nil {
		t.Fatal(err)
	}
	if first.RunID == second.RunID || first.ServerID != second.ServerID {
		t.Fatal("run generation or label-independent identity is incorrect")
	}
	before := second.Backend.LeaseExpiresAt
	if o.Stop(first.RunID) != (Error{Inactive}) || o.RenewLease(first.RunID) != (Error{Inactive}) {
		t.Fatal("stale client request affected replacement")
	}
	current, err := o.Adopt()
	if err != nil || current.RunID != second.RunID || !current.Backend.LeaseExpiresAt.Equal(before) || secondResource.closed.Load() != 0 {
		t.Fatal("replacement changed after stale stop/renew")
	}
	if err := o.RenewLease(second.RunID); err != nil {
		t.Fatal(err)
	}
	if err := o.Stop(second.RunID); err != nil || firstResource.closed.Load() != 1 || secondResource.closed.Load() != 1 {
		t.Fatal("replacement ownership cleanup failed")
	}
	if _, err := o.Adopt(); err != (Error{Inactive}) || o.RenewLease(second.RunID) != (Error{Inactive}) {
		t.Fatal("terminal run was adopted or renewed")
	}
	assertPrivateClean(t, s)
}

func TestOwnerRequestCancellationDuringStartupCleansThenAllowsRetry(t *testing.T) {
	s := fakeSupervisor(t)
	o := NewRuntimeOwner(context.Background(), s)
	t.Cleanup(func() { _ = o.Close() })
	profile, access := ownerInputs(t, "bad-auth")
	request, cancel := context.WithCancel(context.Background())
	defer cancel()
	resource := &fakeOwnedResource{}
	result := make(chan error, 1)
	go func() {
		_, err := o.StartLoopback(request, profile, access, strings.Repeat("c", 64), ownerLimits(), resource)
		result <- err
	}()
	waitOwnerListener(t, access.Listen.String())
	cancel()
	select {
	case err := <-result:
		if err != (Error{Cancelled}) || resource.closed.Load() != 1 {
			t.Fatal("startup cancellation lost ownership or cancellation result")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("startup cancellation did not finish")
	}
	assertPrivateClean(t, s)
	profile, access = ownerInputs(t, "ignore-term")
	retryResource := &fakeOwnedResource{}
	retry, err := o.StartLoopback(context.Background(), profile, access, strings.Repeat("c", 64), ownerLimits(), retryResource)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Stop(retry.RunID); err != nil || retryResource.closed.Load() != 1 {
		t.Fatal("safe retry did not clean up")
	}
}

func TestOwnerShutdownDuringStartupAndAfterReadiness(t *testing.T) {
	for _, duringStartup := range []bool{true, false} {
		t.Run(map[bool]string{true: "startup", false: "ready"}[duringStartup], func(t *testing.T) {
			s := fakeSupervisor(t)
			daemon, shutdown := context.WithCancel(context.Background())
			defer shutdown()
			o := NewRuntimeOwner(daemon, s)
			t.Cleanup(func() { _ = o.Close() })
			mode := "ignore-term"
			if duringStartup {
				mode = "bad-auth"
			}
			profile, access := ownerInputs(t, mode)
			resource := &fakeOwnedResource{}
			result := make(chan error, 1)
			go func() {
				_, err := o.StartLoopback(context.Background(), profile, access, strings.Repeat("d", 64), ownerLimits(), resource)
				result <- err
			}()
			if duringStartup {
				waitOwnerListener(t, access.Listen.String())
			} else if err := <-result; err != nil {
				t.Fatal(err)
			}
			shutdown()
			var callers sync.WaitGroup
			for i := 0; i < 8; i++ {
				callers.Add(1)
				go func() {
					defer callers.Done()
					if err := o.Close(); err != nil {
						t.Error("concurrent owner shutdown failed")
					}
				}()
			}
			callers.Wait()
			if duringStartup && <-result != (Error{Cancelled}) {
				t.Fatal("daemon cancellation did not cancel startup")
			}
			if resource.closed.Load() != 1 {
				t.Fatal("shutdown duplicated resource cleanup")
			}
			if _, err := o.Adopt(); err != (Error{Inactive}) {
				t.Fatal("closed owner offered adoption")
			}
			newResource := &fakeOwnedResource{}
			if _, err := o.StartLoopback(context.Background(), profile, access, strings.Repeat("d", 64), ownerLimits(), newResource); err != (Error{Inactive}) || newResource.closed.Load() != 1 {
				t.Fatal("closed owner allowed a new run or retained resource")
			}
			assertPrivateClean(t, s)
		})
	}
}

func TestOwnerFailedCleanupRemainsVisibleAndBlocksReplacement(t *testing.T) {
	s := fakeSupervisor(t)
	o := NewRuntimeOwner(context.Background(), s)
	t.Cleanup(func() { _ = o.Close() })
	profile, access := ownerInputs(t, "ignore-term")
	resource := &fakeOwnedResource{failure: true}
	started, err := o.StartLoopback(context.Background(), profile, access, strings.Repeat("e", 64), ownerLimits(), resource)
	if err != nil {
		t.Fatal(err)
	}
	if o.Stop(started.RunID) != (Error{Cleanup}) {
		t.Fatal("failed cleanup was hidden")
	}
	snapshot, exists := o.Snapshot()
	if !exists || snapshot.Backend.CleanupOK || snapshot.RunID != started.RunID {
		t.Fatal("cleanup failure evidence was discarded")
	}
	newResource := &fakeOwnedResource{}
	if _, err := o.StartLoopback(context.Background(), profile, access, strings.Repeat("e", 64), ownerLimits(), newResource); err != (Error{Cleanup}) || newResource.closed.Load() != 1 {
		t.Fatal("replacement started after unverified cleanup")
	}
	if o.Close() != (Error{Cleanup}) || resource.closed.Load() != 1 {
		t.Fatal("owner shutdown hid or retried failed cleanup")
	}
	assertPrivateClean(t, s)
}

func TestOwnerConcurrentAdmissionStartsOnlyOneOwnedChain(t *testing.T) {
	s := fakeSupervisor(t)
	o := NewRuntimeOwner(context.Background(), s)
	t.Cleanup(func() { _ = o.Close() })
	type input struct {
		profile  connection.Profile
		access   LoopbackAccess
		resource *fakeOwnedResource
	}
	inputs := make([]input, 2)
	for i := range inputs {
		inputs[i].profile, inputs[i].access = ownerInputs(t, "ignore-term")
		inputs[i].resource = &fakeOwnedResource{}
	}
	results := make(chan error, 2)
	for _, in := range inputs {
		go func() {
			_, err := o.StartLoopback(context.Background(), in.profile, in.access, strings.Repeat("f", 64), ownerLimits(), in.resource)
			results <- err
		}()
	}
	first, second := <-results, <-results
	if !((first == nil && second == (Error{Busy})) || (second == nil && first == (Error{Busy}))) {
		t.Fatal("concurrent admission did not produce one run and one refusal")
	}
	adopted, err := o.Adopt()
	if err != nil {
		t.Fatal(err)
	}
	var callers sync.WaitGroup
	for i := 0; i < 8; i++ {
		callers.Add(1)
		go func() {
			defer callers.Done()
			_ = o.RenewLease(adopted.RunID)
			_, _ = o.Adopt()
			if err := o.Stop(adopted.RunID); err != nil {
				t.Error("concurrent stop failed")
			}
		}()
	}
	callers.Wait()
	for _, in := range inputs {
		if in.resource.closed.Load() != 1 {
			t.Fatal("concurrent admission/stop did not release each resource once")
		}
	}
	assertPrivateClean(t, s)
}

func TestOwnerRefusesInvalidIdentityAndProfileWithoutSpawning(t *testing.T) {
	s := fakeSupervisor(t)
	o := NewRuntimeOwner(context.Background(), s)
	defer o.Close()
	profile, access := ownerInputs(t, "private-secret")
	for _, fingerprint := range []string{"", "private-secret", strings.Repeat("A", 64), strings.Repeat("0", 63)} {
		resource := &fakeOwnedResource{}
		if _, err := o.StartLoopback(context.Background(), profile, access, fingerprint, ownerLimits(), resource); err != (Error{InvalidPlan}) || resource.closed.Load() != 1 {
			t.Fatal("invalid executable identity was accepted or resource retained")
		}
	}
	profile.Host = "remote.example.test"
	resource := &fakeOwnedResource{}
	if _, err := o.StartLoopback(context.Background(), profile, access, strings.Repeat("0", 64), ownerLimits(), resource); err != (connection.Error{Field: "host"}) || resource.closed.Load() != 1 {
		t.Fatal("owner accepted a remote profile or lost its static field error")
	}
	if _, exists := o.Snapshot(); exists {
		t.Fatal("refused data created a runtime slot")
	}
	assertPrivateClean(t, s)
}
