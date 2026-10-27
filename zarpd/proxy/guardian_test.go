package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func fixtureFrame(writer *os.File, data []byte) error {
	if err := writer.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	_, err := writer.Write(append(header[:], data...))
	return err
}

func guardianWorkerFixture(member bool) {
	root, err := os.Getwd()
	if err != nil {
		os.Exit(71)
	}
	executable, err := os.Executable()
	if err != nil {
		os.Exit(71)
	}
	data, err := os.ReadFile(executable)
	if err != nil {
		os.Exit(71)
	}
	digest := sha256.Sum256(data)
	s, err := NewSupervisor(root)
	if member {
		s, err = NewParentSessionSupervisor(root)
	}
	if err != nil {
		os.Exit(71)
	}
	s.specs = map[Engine]engineSpec{SingBox: {"test-engine", "1.13.14", hex.EncodeToString(digest[:]), "sing-box version 1.13.14\n"}}
	if member {
		if _, err := os.Stat("crash-during-startup"); err == nil {
			go func() {
				for {
					paths, _ := filepath.Glob(filepath.Join(os.TempDir(), "zarp-engine-*", "descendant.json"))
					if len(paths) != 0 {
						self, _ := os.FindProcess(os.Getpid())
						_ = self.Kill() // Only this controlled fixture kills itself.
						return
					}
					time.Sleep(10 * time.Millisecond)
				}
			}()
		}
	}
	if RunLoopbackGuardian(context.Background(), os.NewFile(3, "fixture-control"), os.NewFile(4, "fixture-report"), s) != nil {
		os.Exit(72)
	}
}

// This private fake daemon owns the guardian control writer exclusively. Killing
// this exact test process closes it in the kernel; no installed PID is involved.
func guardianParentFixture() {
	input := os.NewFile(3, "fixture-parent-input")
	report := os.NewFile(4, "fixture-parent-report")
	defer input.Close()
	defer report.Close()
	inputFD := int(input.Fd())
	if !prepareGuardianPipe(inputFD, unix.O_RDONLY) {
		os.Exit(73)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	data, err := readGuardianFrame(ctx, inputFD, guardianFrameLimit)
	if err != nil {
		os.Exit(73)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		os.Exit(73)
	}
	executable, _ := os.Executable()
	root, _ := os.Getwd()
	child := exec.Command(executable, "private-guardian-worker")
	child.Dir = root
	child.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "TMPDIR=" + root}
	child.ExtraFiles = []*os.File{reader, report}
	child.Stdout, child.Stderr = io.Discard, io.Discard
	child.WaitDelay = 200 * time.Millisecond
	if child.Start() != nil {
		os.Exit(73)
	}
	_ = reader.Close()
	_ = report.Close()
	if fixtureFrame(writer, data) != nil {
		_ = writer.Close()
		_ = child.Wait()
		os.Exit(73)
	}
	for {
		data, err := readGuardianFrame(ctx, inputFD, 256)
		if err != nil || fixtureFrame(writer, data) != nil {
			break
		}
	}
	_ = writer.Close()
	if child.Wait() != nil {
		os.Exit(73)
	}
}

type guardianFixture struct {
	parent   *exec.Cmd
	done     chan struct{}
	control  *os.File
	report   *os.File
	reportFD int
}

func startGuardianFixture(t *testing.T, s *Supervisor, start GuardianStart) *guardianFixture {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	reportReader, reportWriter, err := os.Pipe()
	if err != nil {
		_ = reader.Close()
		_ = writer.Close()
		t.Fatal(err)
	}
	executable, _ := os.Executable()
	parent := exec.Command(executable, "private-guardian-parent")
	parent.Dir = s.root
	parent.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "TMPDIR=" + s.root}
	parent.ExtraFiles = []*os.File{reader, reportWriter}
	parent.Stdout, parent.Stderr = io.Discard, io.Discard
	parent.WaitDelay = 200 * time.Millisecond
	if err := parent.Start(); err != nil {
		_ = reader.Close()
		_ = writer.Close()
		_ = reportReader.Close()
		_ = reportWriter.Close()
		t.Fatal(err)
	}
	_ = reader.Close()
	_ = reportWriter.Close()
	f := &guardianFixture{parent: parent, done: make(chan struct{}), control: writer, report: reportReader, reportFD: int(reportReader.Fd())}
	go func() { _ = parent.Wait(); close(f.done) }()
	t.Cleanup(func() {
		_ = writer.Close()
		select {
		case <-f.done:
		case <-time.After(4 * time.Second):
			_ = parent.Process.Kill() // Only the unreaped handle created above.
			<-f.done
		}
		_ = reportReader.Close()
	})
	if !prepareGuardianPipe(f.reportFD, unix.O_RDONLY) {
		t.Fatal("test report pipe ownership invalid")
	}
	data, err := json.Marshal(start)
	if err != nil || fixtureFrame(writer, data) != nil {
		t.Fatal("private start frame failed")
	}
	return f
}

func (f *guardianFixture) next(t *testing.T) GuardianReport {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	data, err := readGuardianFrame(ctx, f.reportFD, guardianFrameLimit)
	var report GuardianReport
	if err != nil || json.Unmarshal(data, &report) != nil || report.Version != guardianVersion {
		t.Fatal("bounded guardian report missing or invalid")
	}
	for _, value := range []string{"private-", "127.0.0.1", "outer.example.test"} {
		if strings.Contains(string(data), value) {
			t.Fatal("guardian report exposed private input")
		}
	}
	return report
}

func (f *guardianFixture) verifyEOF(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := readGuardianFrame(ctx, f.reportFD, guardianFrameLimit); err != io.EOF {
		t.Fatal("guardian or its engine retained the private report writer")
	}
}

func TestGuardianRealParentDeathStopsOnlyItsPrivateEngine(t *testing.T) {
	s := fakeSupervisor(t)
	plan := testPlan(t, "ignore-term")
	f := startGuardianFixture(t, s, GuardianStart{Version: guardianVersion, Plan: plan, Limits: ownerLimits()})
	ready := f.next(t)
	if ready.Phase != "ready" || ready.Status.State != Ready || !authenticateListener(context.Background(), plan) {
		t.Fatal("private engine did not become authenticated and ready")
	}
	// Preserve a separate private listener, proving cleanup does not target names,
	// ports, groups or all engines. It is independent of the killed fake daemon.
	independent, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer independent.Close()
	if err := f.parent.Process.Kill(); err != nil {
		t.Fatal("owned fake-daemon crash could not be injected")
	}
	<-f.done
	final := f.next(t)
	if final.Phase != "final" || final.Code != ControlLost || final.Status.State != Stopped || !final.Status.CleanupOK {
		t.Fatal("parent death did not produce verified engine cleanup")
	}
	f.verifyEOF(t)
	assertPrivateClean(t, s)
	if conn, err := net.DialTimeout("tcp", plan.Listen.String(), 100*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatal("owned engine listener survived the fake-daemon crash")
	}
	conn, err := net.DialTimeout("tcp", independent.Addr().String(), 100*time.Millisecond)
	if err != nil {
		t.Fatal("independent listener was disturbed")
	}
	_ = conn.Close()
}

func TestGuardianRenewalAndExplicitStopKeepFiniteOwnership(t *testing.T) {
	s := fakeSupervisor(t)
	plan := testPlan(t, "ignore-term")
	limits := Limits{StartupTimeout: 4 * time.Second, Lifetime: 5 * time.Second, StopGrace: 20 * time.Millisecond}
	f := startGuardianFixture(t, s, GuardianStart{Version: guardianVersion, Plan: plan, Limits: limits})
	ready := f.next(t)
	if ready.Phase != "ready" {
		t.Fatal("private startup failed")
	}
	if fixtureFrame(f.control, []byte(`{"version":1,"action":"renew"}`)) != nil {
		t.Fatal("renew frame failed")
	}
	time.Sleep(time.Until(ready.Status.LeaseExpiresAt.Add(30 * time.Millisecond)))
	if !authenticateListener(context.Background(), plan) {
		t.Fatal("guardian renewal failed to preserve original child past deadline")
	}
	if fixtureFrame(f.control, []byte(`{"version":1,"action":"stop"}`)) != nil {
		t.Fatal("stop frame failed")
	}
	final := f.next(t)
	if final.Phase != "final" || final.Code != Cancelled || final.Status.State != Stopped || !final.Status.CleanupOK {
		t.Fatal("explicit stop did not close the owned child")
	}
	f.verifyEOF(t)
	assertPrivateClean(t, s)
}

func TestGuardianMalformedControlTearsDownReadyEngine(t *testing.T) {
	s := fakeSupervisor(t)
	f := startGuardianFixture(t, s, GuardianStart{Version: guardianVersion, Plan: testPlan(t, "ignore-term"), Limits: ownerLimits()})
	if f.next(t).Phase != "ready" {
		t.Fatal("private engine startup failed")
	}
	if fixtureFrame(f.control, []byte(`{"version":1,"action":"renew","action":"stop","binary":"private-secret"}`)) != nil {
		t.Fatal("malformed test frame failed")
	}
	final := f.next(t)
	if final.Phase != "final" || final.Code != InvalidControl || !final.Status.CleanupOK {
		t.Fatal("malformed control did not cancel and clean the owned engine")
	}
	f.verifyEOF(t)
	assertPrivateClean(t, s)
}

func TestGuardianRejectsInvalidStartBeforeExecution(t *testing.T) {
	s := fakeSupervisor(t)
	start := GuardianStart{Version: guardianVersion, Plan: testPlan(t, "private-secret"), Limits: ownerLimits()}
	encoded, _ := json.Marshal(start)
	for _, data := range [][]byte{
		[]byte(`{"version":1,"version":1,"plan":{},"limits":{}}`),
		[]byte(`{"version":1,"plan":{},"limits":{},"binary":"private-secret"}`),
		[]byte(strings.Replace(string(encoded), `"Engine":`, `"engine":`, 1)),
		[]byte(strings.Replace(string(encoded), `"Lifetime":`, `"lifetime":`, 1)),
		[]byte(strings.Replace(string(encoded), `"version":1`, `"version":1.0`, 1)),
		[]byte(strings.Replace(string(encoded), `"Credential":`, `"binary":"private-secret","Credential":`, 1)),
		[]byte(strings.Repeat(" ", guardianFrameLimit+1)),
	} {
		var decoded GuardianStart
		if decodeGuardianStart(data, &decoded) != (Error{InvalidControl}) {
			t.Fatal("invalid or ambiguous start was accepted")
		}
	}
	var decoded GuardianStart
	if decodeGuardianStart(encoded, &decoded) != nil {
		t.Fatal("valid bounded start refused")
	}
	assertPrivateClean(t, s)
}

func TestGuardianReportBackpressureIsBoundedAndRegularFilesAreRefused(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	fd := int(writer.Fd())
	if !prepareGuardianPipe(fd, unix.O_WRONLY) {
		t.Fatal("owned anonymous pipe refused")
	}
	for total := 0; total < 2<<20; {
		n, err := unix.Write(fd, make([]byte, 8192))
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			break
		}
		if err != nil || n <= 0 {
			t.Fatal("backpressure fixture failed")
		}
		total += n
	}
	before := time.Now()
	if writeGuardianReport(fd, GuardianReport{Version: guardianVersion, Phase: "final"}) || time.Since(before) > 3*time.Second {
		t.Fatal("report write was unbounded or ignored a full pipe")
	}
	file, err := os.Create(filepath.Join(t.TempDir(), "private-control"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if prepareGuardianPipe(int(file.Fd()), unix.O_RDWR) {
		t.Fatal("ordinary file treated as inherited control pipe")
	}
}
