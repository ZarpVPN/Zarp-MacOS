package proxy

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type descendantIdentity struct{ PID, Group, Session int }

func descendantFixture() {
	signal.Ignore(unix.SIGTERM)
	group, err := unix.Getpgid(0)
	if err != nil {
		os.Exit(74)
	}
	session, err := unix.Getsid(0)
	if err != nil {
		os.Exit(74)
	}
	data, _ := json.Marshal(descendantIdentity{PID: os.Getpid(), Group: group, Session: session})
	if os.WriteFile("descendant.json", data, 0600) != nil {
		os.Exit(74)
	}
	if len(os.Args) == 2 && os.Args[1] == "private-descendant-new-group" {
		// An independently bounded changed-group fixture must end itself. No
		// caller is allowed to signal the observed numeric PID/group.
		time.Sleep(6 * time.Second)
		return
	}
	for {
		time.Sleep(time.Hour)
	}
}

func waitDescendant(t *testing.T, directory string) descendantIdentity {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(filepath.Join(directory, "descendant.json"))
		var identity descendantIdentity
		if err == nil && json.Unmarshal(data, &identity) == nil && identity.PID > 0 {
			return identity
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("controlled descendant did not start")
	return descendantIdentity{}
}

func TestOwnedGroupCleanupBeforeReapingPreservesUnrelatedChild(t *testing.T) {
	s := fakeSupervisor(t)
	independent, err := s.StartLoopback(context.Background(), testPlan(t, "ignore-term"), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = independent.Close() })
	session, err := s.StartLoopback(context.Background(), testPlan(t, "spawn-descendant"), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	identity := waitDescendant(t, session.dir)
	leader := session.child.cmd.Process.Pid
	if identity.PID == leader || identity.Group != leader || identity.Session != leader {
		t.Fatal("descendant did not belong to the new private group/session")
	}
	if live, err := ownedGroupLive(leader, false); err != nil || live < 2 {
		t.Fatal("native ownership did not observe engine plus descendant")
	}
	if err := session.Close(); err != nil || !session.Status().CleanupOK {
		t.Fatal("owned TERM-ignoring group cleanup failed")
	}
	if live, err := ownedGroupLive(leader, true); err != nil || live != 0 {
		t.Fatal("live group members survived cleanup")
	}
	if session.child.signalGroup(unix.SIGKILL) {
		t.Fatal("reaped object permitted a stale group signal")
	}
	if _, ready := independent.readyStatus(); !ready {
		t.Fatal("independent owned child was disturbed")
	}
	if err := independent.Close(); err != nil {
		t.Fatal(err)
	}
	assertPrivateClean(t, s)
}

func TestOwnedLeaderEarlyExitDoesNotLeaveDescendantOrInheritedOutput(t *testing.T) {
	s := fakeSupervisor(t)
	directory := t.TempDir()
	binary, err := s.snapshot(context.Background(), s.specs[SingBox], directory)
	if err != nil {
		t.Fatal(err)
	}
	plan := testPlan(t, "spawn-descendant-exit")
	data, err := plan.compile()
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(directory, "config.json")
	if os.WriteFile(config, data, 0600) != nil {
		t.Fatal("private config write failed")
	}
	child, err := startChild(binary, directory, []string{"run", "-c", config}, &boundedOutput{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.stop(20 * time.Millisecond) })
	identity := waitDescendant(t, directory)
	if identity.Group != child.cmd.Process.Pid || identity.Session != child.cmd.Process.Pid {
		t.Fatal("early-exit descendant escaped the private session")
	}
	select {
	case <-child.done:
	case <-time.After(4 * time.Second):
		t.Fatal("leader exit left a live descendant or output pipe")
	}
	if !child.clean || child.cmd.ProcessState == nil || child.err != nil {
		t.Fatal("successful leader exit did not verify and reap full private group")
	}
	if child.signalGroup(unix.SIGTERM) {
		t.Fatal("terminal child object allowed a group signal")
	}
	if live, err := ownedGroupLive(child.cmd.Process.Pid, true); err != nil || live != 0 {
		t.Fatal("early-exit group remains live")
	}
}

func TestNativeOwnershipRejectsNonChildWithoutSignals(t *testing.T) {
	// The caller itself is never its own unreaped child. This checks the native
	// ownership condition without inspecting or signaling an installed process.
	if _, err := ownedChildExited(os.Getpid()); err == nil {
		t.Fatal("non-child was considered owned")
	}
}

func TestReadyLeaseChecksActualChildExitBeforeCleanupWatcher(t *testing.T) {
	s := fakeSupervisor(t)
	directory := t.TempDir()
	binary, err := s.snapshot(context.Background(), s.specs[SingBox], directory)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "version")
	command.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "TMPDIR=" + directory}
	command.Dir = directory
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if command.Start() != nil {
		t.Fatal("owned version fixture did not start")
	}
	defer command.Wait() // Only this test reaps; no watcher runs for this fixture.
	deadline := time.Now().Add(4 * time.Second)
	exited := false
	for time.Now().Before(deadline) {
		exited, err = ownedChildExited(command.Process.Pid)
		if err != nil || exited {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil || !exited {
		t.Fatal("native unreaped exit observation failed")
	}
	child := &ownedChild{cmd: command, done: make(chan struct{}), output: &boundedOutput{}}
	status := Status{State: Ready, LeaseExpiresAt: time.Now().Add(time.Minute)}
	session := &Session{ctx: context.Background(), child: child, status: status}
	guarded := &GuardedSession{ctx: context.Background(), child: child, status: status}
	for _, run := range []runtimeSession{session, guarded} {
		if _, ready := run.readyStatus(); ready || run.RenewLease() != (Error{Inactive}) {
			t.Fatal("an exited child was adopted or renewed before watcher completion")
		}
	}
}
