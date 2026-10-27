package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Private fixture proof is never an adoption or signal authority. The test
// signals only its own unreaped direct fake-daemon child. Directory/SID data is
// used for read-only checks; no installed process or service is involved.
type typedOwnerProof struct {
	Directory string
	Session   int
	Failure   Code `json:"failure,omitempty"`
}

func typedGuardianOwnerFixture() {
	control, report := os.NewFile(3, "fixture-owner-control"), os.NewFile(4, "fixture-owner-report")
	defer control.Close()
	defer report.Close()
	controlFD, reportFD := int(control.Fd()), int(report.Fd())
	fail := func(code Code) {
		data, _ := json.Marshal(typedOwnerProof{Failure: code})
		_ = writeGuardianFrame(reportFD, data)
		os.Exit(76)
	}
	if !prepareGuardianPipe(controlFD, unix.O_RDONLY) || !prepareGuardianPipe(reportFD, unix.O_WRONLY) {
		fail(InvalidControl)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	data, err := readGuardianFrame(ctx, controlFD, guardianFrameLimit)
	var start GuardianStart
	if err != nil || decodeGuardianStart(data, &start) != nil {
		fail(InvalidPlan)
	}
	root, _ := os.Getwd()
	executable, _ := os.Executable()
	bytes, err := os.ReadFile(executable)
	if err != nil {
		fail(BinaryUnavailable)
	}
	digest := sha256.Sum256(bytes)
	pin := hex.EncodeToString(digest[:])
	g, err := NewLoopbackGuardianLauncher(root, pin, root)
	if err != nil {
		fail(InvalidInventory)
	}
	g.inventory.specs = map[Engine]engineSpec{SingBox: {"test-engine", "1.13.14", pin, "sing-box version 1.13.14\n"}}
	// Startup proof is sent only after an actual engine descendant exists. That
	// engine cannot start until the recovery helper has acknowledged arming.
	if start.Plan.Credential == "spawn-descendant-no-listener" {
		go func() {
			for ctx.Err() == nil {
				paths, _ := filepath.Glob(filepath.Join(root, "zarp-guardian-*", "zarp-engine-*", "descendant.json"))
				if len(paths) == 1 {
					data, _ := os.ReadFile(paths[0])
					var member descendantIdentity
					if json.Unmarshal(data, &member) == nil && member.Session > 1 {
						proof, _ := json.Marshal(typedOwnerProof{Directory: filepath.Dir(filepath.Dir(paths[0])), Session: member.Session})
						_ = writeGuardianFrame(reportFD, proof)
						return
					}
				}
				time.Sleep(10 * time.Millisecond)
			}
		}()
	}
	session, err := g.StartLoopback(ctx, start.Plan, start.Limits)
	if err != nil {
		code := Startup
		if failure, ok := err.(Error); ok {
			code = failure.Code
		}
		data, _ := json.Marshal(typedOwnerProof{Failure: code})
		_ = writeGuardianFrame(reportFD, data)
		os.Exit(76)
	}
	defer session.Close()
	runtime.GC() // Raw descriptors must remain backed by the deferred file owners.
	proof, _ := json.Marshal(typedOwnerProof{Directory: session.dir, Session: session.child.cmd.Process.Pid})
	if !writeGuardianFrame(reportFD, proof) {
		os.Exit(76)
	}
	data, err = readGuardianFrame(ctx, controlFD, 128)
	if err == nil && string(data) == `{"action":"crash-both"}` {
		if !session.child.signalLeader(unix.SIGKILL) {
			os.Exit(76)
		}
		// This exact fixture kills itself. It cannot accept any target PID.
		self, _ := os.FindProcess(os.Getpid())
		_ = self.Kill()
	}
}

func startTypedGuardianOwnerFixture(t *testing.T, s *Supervisor, start GuardianStart, probe ...bool) (*ownedChild, *os.File, *os.File) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal("private owner input unavailable")
	}
	reportReader, reportWriter, err := os.Pipe()
	if err != nil {
		t.Fatal("private owner report unavailable")
	}
	action := "private-typed-guardian-owner"
	if len(probe) > 0 && probe[0] {
		action = "private-owner-probe-api"
	}
	child, err := startChildConstructed(filepath.Join(s.root, "test-engine"), s.root, s.root,
		[]string{action}, &boundedOutput{}, []*os.File{reader, reportWriter}, true)
	_ = reader.Close()
	_ = reportWriter.Close()
	if err != nil {
		_ = writer.Close()
		_ = reportReader.Close()
		t.Fatal("owned fake daemon did not start")
	}
	t.Cleanup(func() { _ = writer.Close(); _ = reportReader.Close(); _ = child.stop(20 * time.Millisecond) })
	data, _ := json.Marshal(start)
	if fixtureFrame(writer, data) != nil {
		t.Fatal("private owner start handoff failed")
	}
	return child, writer, reportReader
}

func TestRecoverySurvivesTypedOwnerDeathAndBothOwnersDeath(t *testing.T) {
	for _, variant := range []string{"daemon", "daemon-and-guardian", "startup"} {
		t.Run(variant, func(t *testing.T) {
			_, s := fakeLauncher(t)
			independent, err := s.StartLoopback(context.Background(), testPlan(t, "ignore-term"), DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = independent.Close() })
			mode := "spawn-descendant"
			if variant == "startup" {
				mode = "spawn-descendant-no-listener"
			}
			plan := testPlan(t, mode)
			child, writer, reader := startTypedGuardianOwnerFixture(t, s, GuardianStart{Version: 1, Plan: plan, Limits: ownerLimits()})
			fd := int(reader.Fd())
			if !prepareGuardianPipe(fd, unix.O_RDONLY) {
				t.Fatal("private proof input invalid")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			data, err := readGuardianFrame(ctx, fd, 1024)
			var proof typedOwnerProof
			if err != nil || json.Unmarshal(data, &proof) != nil || filepath.Dir(proof.Directory) != s.root ||
				!recoveryRootNameForFixture(proof.Directory) || proof.Session <= 1 {
				t.Logf("private proof read_error=%v bytes=%d failure=%s matching_parent=%v session_observed=%v", err, len(data), proof.Failure, filepath.Dir(proof.Directory) == s.root, proof.Session > 1)
				t.Fatal("private typed owner proof missing or outside its directory")
			}
			paths, _ := filepath.Glob(filepath.Join(proof.Directory, "zarp-engine-*", "descendant.json"))
			if len(paths) != 1 {
				t.Fatal("actual private descendant proof missing")
			}
			member := waitDescendant(t, filepath.Dir(paths[0]))
			if member.Group != proof.Session || member.Session != proof.Session {
				t.Fatal("descendant escaped the reserved private group")
			}
			if variant == "daemon-and-guardian" {
				if fixtureFrame(writer, []byte(`{"action":"crash-both"}`)) != nil {
					t.Fatal("owned crash handoff failed")
				}
			} else if !child.signalLeader(unix.SIGKILL) {
				t.Fatal("exact fake daemon crash failed")
			}
			select {
			case <-child.done:
			case <-time.After(5 * time.Second):
				t.Fatal("owned fake daemon did not exit")
			}
			deadline := time.Now().Add(5 * time.Second)
			clean := false
			for time.Now().Before(deadline) {
				_, err := os.Lstat(proof.Directory)
				group, ge := ownedGroupLive(proof.Session, true)
				members, se := ownedSessionLive(proof.Session)
				if os.IsNotExist(err) && ge == nil && se == nil && group == 0 && members == 0 {
					clean = true
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if !clean || authenticateListener(context.Background(), plan) {
				t.Fatal("recovery left private files, engine or descendant after owner death")
			}
			if _, ready := independent.readyStatus(); !ready {
				t.Fatal("private recovery disturbed an unrelated engine")
			}
			if err := independent.Close(); err != nil {
				t.Fatal(err)
			}
			assertLauncherClean(t, s.root)
		})
	}
}

func recoveryRootNameForFixture(directory string) bool {
	base := filepath.Base(directory)
	return len(base) > len("zarp-guardian-") && base[:len("zarp-guardian-")] == "zarp-guardian-"
}

func TestRecoveryAuthorityAndReplacedDirectoryRefuse(t *testing.T) {
	if recoverySessionHeld(os.Getpid()) {
		t.Fatal("caller acquired unrelated session authority")
	}
	if _, err := recoverySession(); err == nil {
		t.Fatal("ordinary caller acquired guardian recovery authority")
	}
	parent := t.TempDir()
	root, err := os.MkdirTemp(parent, "zarp-guardian-")
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	capability := os.NewFile(uintptr(fd), "fixture-root")
	defer capability.Close()
	if !recoveryRootMatches(capability, root) {
		t.Fatal("owned private root capability refused")
	}
	if os.Rename(root, root+"-retained") != nil || os.Mkdir(root, 0700) != nil {
		t.Fatal("replacement fixture unavailable")
	}
	if recoveryRootMatches(capability, root) {
		t.Fatal("replacement directory acquired old cleanup authority")
	}
	if os.Chmod(root+"-retained", 0755) != nil {
		t.Fatal("permission fixture unavailable")
	}
	if recoveryRootMatches(capability, root+"-retained") {
		t.Fatal("public root acquired cleanup authority")
	}
}

func TestRecoveryIdentityRejectsArbitraryTargetsSecretsAndVersions(t *testing.T) {
	valid := []byte(`{"version":1,"engine":"sing-box","build":"1.13.14"}`)
	var identity recoveryIdentity
	if !decodeRecoveryIdentity(valid, &identity) {
		t.Fatal("fixed identity refused")
	}
	for _, data := range [][]byte{
		[]byte(`{"version":1,"engine":"sing-box","build":"1.13.14","pid":12345}`),
		[]byte(`{"version":1,"engine":"sing-box","build":"1.13.14","root":"private-secret"}`),
		[]byte(`{"version":1,"engine":"sing-box","build":"private-secret"}`),
		[]byte(`{"version":1,"engine":"sing-box","build":"1.13.14","version":1}`),
		[]byte(`{"Version":1,"engine":"sing-box","build":"1.13.14"}`),
		[]byte(`{"version":true,"engine":"sing-box","build":"1.13.14"}`),
		[]byte(`{"version":1,"engine":"arbitrary-engine","build":"1.13.14"}`),
	} {
		if decodeRecoveryIdentity(data, &identity) {
			t.Fatal("untrusted recovery identity accepted")
		}
	}
}

func TestRecoveryChangedGroupRetainsFailureUntilOwnedMembersEnd(t *testing.T) {
	g, s := fakeLauncher(t)
	session, err := g.StartLoopback(context.Background(), testPlan(t, "spawn-descendant-new-group"), ownerLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	paths, _ := filepath.Glob(filepath.Join(session.dir, "zarp-engine-*", "descendant.json"))
	if len(paths) != 1 {
		t.Fatal("changed-group fixture did not start")
	}
	member := waitDescendant(t, filepath.Dir(paths[0]))
	leader := session.child.cmd.Process.Pid
	if member.Group == leader || member.Session != leader {
		t.Fatal("fixture did not change group inside the reserved session")
	}
	if session.Close() != (Error{Cleanup}) || session.Status().CleanupOK {
		t.Fatal("changed group was reported as complete cleanup")
	}
	if _, err := os.Stat(session.dir); err != nil {
		t.Fatal("unverified cleanup removed the owned private files")
	}
	select {
	case <-session.child.done:
		remaining, queryErr := ownedSessionLive(leader)
		t.Fatalf("reserved leader watch ended with a changed-group member: reaped=%v clean=%v child_error=%v remaining=%d query_error=%v",
			session.child.reaped.Load(), session.child.clean, session.child.err, remaining, queryErr)
	default:
	}
	// This fixture exits under its own six-second cap. The test neither
	// targets that observed PID nor broadens the original private group.
	select {
	case <-session.child.done:
	case <-time.After(8 * time.Second):
		t.Fatal("bounded changed-group fixture did not finish")
	}
	if !session.child.clean || session.Status().CleanupOK {
		t.Fatal("late exit revived a failed cleanup result or lost native ownership")
	}
	if remaining, err := ownedSessionLive(leader); err != nil || remaining != 0 {
		t.Fatal("private session members survived their independent cap")
	}
	if os.RemoveAll(session.dir) != nil {
		t.Fatal("verified fixture file cleanup failed")
	}
	assertLauncherClean(t, s.root)
}

func ownerProbeAPIFixture() {
	root, _ := os.Getwd()
	executable, _ := os.Executable()
	data, err := os.ReadFile(executable)
	if err != nil {
		os.Exit(77)
	}
	digest := sha256.Sum256(data)
	pin := hex.EncodeToString(digest[:])
	g, err := NewLoopbackGuardianLauncher(root, pin, root)
	if err != nil {
		os.Exit(77)
	}
	g.inventory.specs = map[Engine]engineSpec{SingBox: {"test-engine", "1.13.14", pin, "sing-box version 1.13.14\n"}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if RunLoopbackOwnerProbe(ctx, os.NewFile(3, "fixture-probe-input"), os.NewFile(4, "fixture-probe-output"), g) != nil {
		os.Exit(77)
	}
}

func TestOwnerProbeRejectsAmbiguousStopAfterVerifiedCleanup(t *testing.T) {
	for _, control := range []string{`{"version":1,"action":"stop"}`, `{"version":1,"action":"stop","version":1}`} {
		t.Run(control, func(t *testing.T) {
			_, s := fakeLauncher(t)
			child, writer, reader := startTypedGuardianOwnerFixture(t, s, GuardianStart{Version: 1, Plan: testPlan(t, "ignore-term"), Limits: ownerLimits()}, true)
			fd := int(reader.Fd())
			if !prepareGuardianPipe(fd, unix.O_RDONLY) {
				t.Fatal("private probe report unavailable")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			read := func() OwnerProbeReport {
				t.Helper()
				data, err := readGuardianFrame(ctx, fd, 2048)
				var report OwnerProbeReport
				if err != nil || json.Unmarshal(data, &report) != nil || report.Version != 1 {
					t.Fatal("private probe evidence missing")
				}
				return report
			}
			ready := read()
			if ready.Phase != "ready" || ready.Status.State != Ready || ready.SessionID <= 1 || ready.Directory == "" {
				t.Fatal("private probe did not authenticate its engine")
			}
			if fixtureFrame(writer, []byte(control)) != nil {
				t.Fatal("private stop handoff failed")
			}
			final := read()
			if final.Phase != "final" || !final.Status.CleanupOK {
				t.Fatal("private probe stop did not verify cleanup")
			}
			select {
			case <-child.done:
			case <-ctx.Done():
				t.Fatal("private probe did not exit")
			}
			if !child.clean || (child.err == nil) != (control == `{"version":1,"action":"stop"}`) {
				t.Fatal("ambiguous stop was accepted or normal stop failed")
			}
			if _, err := os.Lstat(ready.Directory); !os.IsNotExist(err) || !ProbeSessionEmpty(ready.SessionID) {
				t.Fatal("private probe left a recovery session or files")
			}
			assertLauncherClean(t, s.root)
		})
	}
}
