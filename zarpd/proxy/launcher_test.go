package proxy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func fakeLauncher(t *testing.T) (*GuardianLauncher, *Supervisor) {
	t.Helper()
	s := fakeSupervisor(t)
	data, err := os.ReadFile(filepath.Join(s.root, "test-engine"))
	if err != nil || os.WriteFile(filepath.Join(s.root, "parity-backend-guardian"), data, 0700) != nil {
		t.Fatal("private guardian fixture unavailable")
	}
	g, err := NewLoopbackGuardianLauncher(s.root, s.specs[SingBox].digest, s.root)
	if err != nil {
		t.Fatal(err)
	}
	g.inventory.specs = s.specs
	return g, s
}

func assertLauncherClean(t *testing.T, root string) {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal("private run directory unavailable")
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "zarp-guardian-") || strings.HasPrefix(entry.Name(), "zarp-engine-") {
			t.Fatal("guardian or engine private resources survived verified cleanup")
		}
	}
}

func TestLauncherOwnerAdoptionRenewalAndConcurrentClose(t *testing.T) {
	g, s := fakeLauncher(t)
	owner := NewRuntimeOwner(context.Background(), g)
	t.Cleanup(func() { _ = owner.Close() })
	request, disappear := context.WithCancel(context.Background())
	defer disappear()
	profile, access := ownerInputs(t, "spawn-descendant")
	resource := &fakeOwnedResource{}
	limits := Limits{StartupTimeout: 4 * time.Second, Lifetime: 5 * time.Second, StopGrace: 20 * time.Millisecond}
	started, err := owner.StartLoopback(request, profile, access, strings.Repeat("c", 64), limits, resource)
	if err != nil {
		t.Fatal(err)
	}
	session := owner.run.chain.engine.(*GuardedSession)
	leader := session.child.cmd.Process.Pid
	paths, _ := filepath.Glob(filepath.Join(session.dir, "zarp-engine-*", "descendant.json"))
	if len(paths) != 1 {
		t.Fatal("private descendant proof missing")
	}
	identity := waitDescendant(t, filepath.Dir(paths[0]))
	if identity.Group != leader || identity.Session != leader {
		t.Fatal("engine descendant did not remain in guardian's private session")
	}
	disappear()
	adopted, err := owner.Adopt()
	if err != nil || adopted.RunID != started.RunID || owner.run.chain.engine != session {
		t.Fatal("request disappearance cancelled or replaced the guarded run")
	}
	// Renew late enough to extend past the original deadline, then require the
	// acknowledgement to update the adopted status before reporting success.
	original := adopted.Backend.LeaseExpiresAt
	time.Sleep(time.Until(original.Add(-700 * time.Millisecond)))
	if err := owner.RenewLease(started.RunID); err != nil {
		t.Fatal(err)
	}
	current, err := owner.Adopt()
	if err != nil || !current.Backend.LeaseExpiresAt.After(original) {
		t.Fatal("lease renewal did not acknowledge the actual guarded lease")
	}
	time.Sleep(time.Until(original.Add(30 * time.Millisecond)))
	if _, err := owner.Adopt(); err != nil {
		t.Fatal("acknowledged renewal failed past the original deadline")
	}
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() { defer workers.Done(); _ = owner.RenewLease(started.RunID) }()
	}
	if err := owner.Stop(started.RunID); err != nil {
		t.Fatal(err)
	}
	workers.Wait()
	if resource.closed.Load() != 1 || !session.Status().CleanupOK || session.child.signalLeader(unix.SIGKILL) {
		t.Fatal("guarded close was not complete, singular or safe after reaping")
	}
	if owner.RenewLease(started.RunID) != (Error{Inactive}) {
		t.Fatal("terminal guarded run was revived")
	}
	assertLauncherClean(t, s.root)
}

func TestLauncherGuardianCrashCleansEngineAndDescendants(t *testing.T) {
	g, s := fakeLauncher(t)
	independent, err := s.StartLoopback(context.Background(), testPlan(t, "ignore-term"), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = independent.Close() })
	plan := testPlan(t, "spawn-descendant")
	session, err := g.StartLoopback(context.Background(), plan, ownerLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	leader := session.child.cmd.Process.Pid
	if live, err := ownedGroupLive(leader, false); err != nil || live < 3 {
		t.Fatal("guardian, engine and descendant were not observed together")
	}
	if !session.child.signalLeader(unix.SIGKILL) {
		t.Fatal("exact private guardian crash injection failed")
	}
	select {
	case <-session.Done():
	case <-time.After(4 * time.Second):
		t.Fatal("guardian crash left its private run alive")
	}
	if status := session.Status(); status.State != Failed || !status.CleanupOK || !session.child.clean {
		t.Fatal("crashed guardian was confused with successful runtime or cleanup failed")
	}
	if live, err := ownedGroupLive(leader, true); err != nil || live != 0 || authenticateListener(context.Background(), plan) {
		t.Fatal("engine or descendant survived guardian crash")
	}
	if _, ready := independent.readyStatus(); !ready {
		t.Fatal("guardian crash disturbed an unrelated owned engine")
	}
	if err := independent.Close(); err != nil {
		t.Fatal(err)
	}
	assertLauncherClean(t, s.root)
}

func TestLauncherCrashDuringStartupRetainsOwnership(t *testing.T) {
	g, s := fakeLauncher(t)
	if os.WriteFile(filepath.Join(s.root, "crash-during-startup"), []byte("private fixture"), 0600) != nil {
		t.Fatal("private crash fixture unavailable")
	}
	resource := &fakeOwnedResource{}
	chain, err := g.StartLoopbackChain(context.Background(), testPlan(t, "spawn-descendant-no-listener"), ownerLimits(), resource)
	if chain != nil || err == nil || err == (Error{Cleanup}) || resource.closed.Load() != 1 {
		t.Fatal("startup guardian crash lost ownership or reported a ready chain")
	}
	assertLauncherClean(t, s.root)
}

func TestLauncherIntegrityAndCancellationRefuseExecution(t *testing.T) {
	g, s := fakeLauncher(t)
	if os.WriteFile(filepath.Join(s.root, "parity-backend-guardian"), []byte("private-corruption"), 0700) != nil {
		t.Fatal("corrupt fixture unavailable")
	}
	if _, err := g.StartLoopback(context.Background(), testPlan(t, "ignore-term"), ownerLimits()); err != (Error{BinaryIntegrity}) {
		t.Fatal("changed guardian executed or lost its integrity error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := g.StartLoopback(ctx, testPlan(t, "ignore-term"), ownerLimits()); err != (Error{Cancelled}) {
		t.Fatal("cancelled guarded startup attempted execution")
	}
	if _, err := NewLoopbackGuardianLauncher(s.root, "private-untrusted-digest", s.root); err != (Error{InvalidInventory}) {
		t.Fatal("arbitrary guardian policy accepted")
	}
	assertLauncherClean(t, s.root)
}

func TestLauncherReportsRejectAmbiguousOrSecretShapes(t *testing.T) {
	valid := GuardianReport{Version: 1, Phase: "ready", Status: Status{Engine: SingBox, Version: "1.13.14", State: Ready, LeaseExpiresAt: time.Now().Add(time.Minute)}}
	encoded, _ := json.Marshal(valid)
	for _, data := range [][]byte{
		[]byte(strings.Replace(string(encoded), `"version":1`, `"version":1,"version":1`, 1)),
		[]byte(strings.Replace(string(encoded), `"phase":`, `"Phase":`, 1)),
		[]byte(strings.Replace(string(encoded), `"State":`, `"state":`, 1)),
		[]byte(strings.Replace(string(encoded), `"phase":"ready"`, `"phase":"private-secret"`, 1)),
		[]byte(strings.Replace(string(encoded), `"Version":"1.13.14"`, `"Version":"private-secret"`, 1)),
		[]byte(strings.Replace(string(encoded), `"CleanupOK":false`, `"CleanupOK":true`, 1)),
		[]byte(strings.Replace(string(encoded), `"OutputBytes":0`, `"OutputBytes":32769`, 1)),
		[]byte(strings.Replace(string(encoded), `"State":`, `"binary":"private-secret","State":`, 1)),
	} {
		var report GuardianReport
		if decodeGuardianReport(data, &report, SingBox, "1.13.14") != (Error{InvalidControl}) {
			t.Fatal("ambiguous, unbounded or secret report accepted")
		}
	}
	var report GuardianReport
	if decodeGuardianReport(encoded, &report, SingBox, "1.13.14") != nil {
		t.Fatal("valid typed readiness report refused")
	}
}
