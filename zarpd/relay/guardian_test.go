package relay

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	backend "github.com/feg55/zarp-macos/zarpd/proxy"
)

func buildLoopbackGuardian(t *testing.T, directory string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	working, err := os.Getwd()
	if err != nil {
		t.Fatal("private guardian build directory unavailable")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal("local Go module cache unavailable")
	}
	cache := os.Getenv("GOCACHE")
	if cache == "" {
		cache = filepath.Join(directory, "go-cache")
	}
	binaryPath := filepath.Join(directory, "parity-backend-guardian")
	command := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", binaryPath, "./cmd/parity-backend-guardian")
	command.Dir = filepath.Dir(working)
	command.Env = []string{"PATH=/opt/homebrew/bin:/usr/bin:/bin", "LC_ALL=C", "TMPDIR=" + directory,
		"GOTOOLCHAIN=local", "GOENV=off", "GOFLAGS=", "GOOS=darwin", "GOARCH=arm64", "GOCACHE=" + cache,
		"GOMODCACHE=" + filepath.Join(home, "go", "pkg", "mod"), "GOPROXY=off", "GOSUMDB=off"}
	diagnostics := &boundedEngineLog{}
	command.Stdout, command.Stderr = diagnostics, diagnostics
	command.WaitDelay = 200 * time.Millisecond
	if command.Run() != nil {
		t.Fatal("private guardian build failed")
	}
	return binaryPath
}

// The launcher gives the guardian only inherited anonymous pipes and a trusted
// inventory directory. No binary/config path, credentials or arguments travel in
// public argv/environment. Both actual protocols stay on loopback.
func startLoopbackGuardian(t *testing.T, ctx context.Context, guardian, engine, directory string, plan backend.LoopbackPlan, terminate bool) func() {
	t.Helper()
	controlRead, controlWrite, err := os.Pipe()
	if err != nil {
		t.Fatal("private control pipe unavailable")
	}
	reportRead, reportWrite, err := os.Pipe()
	if err != nil {
		_ = controlRead.Close()
		_ = controlWrite.Close()
		t.Fatal("private report pipe unavailable")
	}
	child := exec.Command(guardian)
	child.Dir = filepath.Dir(filepath.Dir(engine))
	child.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "TMPDIR=" + directory}
	child.ExtraFiles = []*os.File{controlRead, reportWrite}
	diagnostics := &boundedEngineLog{}
	child.Stdout, child.Stderr = diagnostics, diagnostics
	child.WaitDelay = 200 * time.Millisecond
	if child.Start() != nil {
		_ = controlRead.Close()
		_ = controlWrite.Close()
		_ = reportRead.Close()
		_ = reportWrite.Close()
		t.Fatal("private guardian startup failed")
	}
	_ = controlRead.Close()
	_ = reportWrite.Close()
	done := make(chan struct{})
	var childError error
	go func() { childError = child.Wait(); close(done) }()
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			expectedCode := backend.ControlLost
			if terminate {
				expectedCode = ""
				_ = child.Process.Signal(syscall.SIGTERM)
			} else {
				_ = controlWrite.Close()
			}
			// EOF uses the same kernel event as the real fake-daemon SIGKILL test.
			final, finalErr := loopbackGuardianReport(reportRead)
			verified := finalErr == nil && final.Phase == "final" && final.Status.CleanupOK
			if !verified || final.Code != expectedCode || final.Status.State != backend.Stopped {
				t.Error("pinned engine did not clean up after control loss")
			}
			_ = controlWrite.Close()
			if !verified {
				// Cooperative SIGTERM invokes the guardian's cleanup handler. Its
				// lease lives in that process; killing it would orphan the engine.
				_ = child.Process.Signal(syscall.SIGTERM)
			}
			select {
			case <-done:
				if childError != nil {
					t.Error("private guardian exited unsuccessfully")
				}
			case <-time.After(8 * time.Second):
				if verified {
					_ = child.Process.Kill() // Engine teardown was already verified.
					<-done
				}
				t.Error("private guardian completion not verified")
			}
			_ = reportRead.Close()
			entries, err := os.ReadDir(directory)
			if err != nil {
				t.Error("private cleanup directory unavailable")
			}
			for _, entry := range entries {
				if len(entry.Name()) >= len("zarp-engine-") && entry.Name()[:len("zarp-engine-")] == "zarp-engine-" {
					t.Error("owned pinned-engine configuration remains")
				}
			}
			if conn, err := net.DialTimeout("tcp", plan.Listen.String(), 100*time.Millisecond); err == nil {
				_ = conn.Close()
				t.Error("pinned engine listener survived guardian cleanup")
			}
		})
	}
	t.Cleanup(cleanup)
	stopContext := context.AfterFunc(ctx, func() { _ = controlWrite.Close() })
	t.Cleanup(func() { stopContext() })
	request := backend.GuardianStart{Version: 1, Plan: plan, Limits: backend.Limits{
		StartupTimeout: 5 * time.Second, Lifetime: 15 * time.Second, StopGrace: 200 * time.Millisecond}}
	data, err := json.Marshal(request)
	if err != nil || controlWrite.SetWriteDeadline(time.Now().Add(2*time.Second)) != nil {
		t.Fatal("private guardian request encoding failed")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	if _, err := controlWrite.Write(append(header[:], data...)); err != nil {
		t.Fatal("private guardian request failed")
	}
	if ready := readLoopbackGuardianReport(t, reportRead); ready.Phase != "ready" || ready.Status.State != backend.Ready {
		t.Fatal("pinned guardian engine was not authenticated and ready")
	}
	return cleanup
}

func readLoopbackGuardianReport(t *testing.T, reader *os.File) backend.GuardianReport {
	t.Helper()
	report, err := loopbackGuardianReport(reader)
	if err != nil {
		t.Fatal("private guardian report missing or invalid")
	}
	return report
}

func loopbackGuardianReport(reader *os.File) (backend.GuardianReport, error) {
	failure := backend.Error{Code: backend.InvalidControl}
	if reader.SetReadDeadline(time.Now().Add(6*time.Second)) != nil {
		return backend.GuardianReport{}, failure
	}
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return backend.GuardianReport{}, failure
	}
	count := binary.BigEndian.Uint32(header[:])
	if count == 0 || count > 32768 {
		return backend.GuardianReport{}, failure
	}
	data := make([]byte, int(count))
	if _, err := io.ReadFull(reader, data); err != nil {
		return backend.GuardianReport{}, failure
	}
	var report backend.GuardianReport
	if json.Unmarshal(data, &report) != nil || report.Version != 1 {
		return backend.GuardianReport{}, failure
	}
	return report, nil
}

// The exact owned parent stays unreaped until the sole cleanup path injects
// SIGKILL. Its anonymous-pipe EOF drives the surviving guardian/recovery member.
func startLoopbackOwnerCrash(t *testing.T, ctx context.Context, guardian, engine, directory string, plan backend.LoopbackPlan) func() {
	t.Helper()
	controlRead, controlWrite, err := os.Pipe()
	if err != nil {
		t.Fatal("private owner control unavailable")
	}
	reportRead, reportWrite, err := os.Pipe()
	if err != nil {
		_ = controlRead.Close()
		_ = controlWrite.Close()
		t.Fatal("private owner report unavailable")
	}
	child := exec.Command(guardian, "--owner-probe")
	child.Dir = filepath.Dir(filepath.Dir(engine))
	child.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "TMPDIR=" + directory}
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	child.ExtraFiles = []*os.File{controlRead, reportWrite}
	diagnostics := &boundedEngineLog{}
	child.Stdout, child.Stderr = diagnostics, diagnostics
	child.WaitDelay = 200 * time.Millisecond
	if child.Start() != nil {
		_ = controlRead.Close()
		_ = controlWrite.Close()
		_ = reportRead.Close()
		_ = reportWrite.Close()
		t.Fatal("private owner did not start")
	}
	_ = controlRead.Close()
	_ = reportWrite.Close()
	var once sync.Once
	root := ""
	sessionID := 0 // Read-only native observation, never passed to a signal.
	cleanup := func() {
		once.Do(func() {
			// Only this path signals and waits. Even an early exit remains an
			// unreaped owned child; no observed or saved numeric PID is used.
			_ = child.Process.Kill()
			_ = controlWrite.Close()
			done := make(chan struct{})
			go func() { _ = child.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("private owner exit not verified")
			}
			if root == "" {
				t.Error("owner supplied no verified private recovery evidence")
				_ = reportRead.Close()
				return
			}
			deadline := time.Now().Add(5 * time.Second)
			removed := false
			for time.Now().Before(deadline) {
				if _, err := os.Lstat(root); os.IsNotExist(err) && backend.ProbeSessionEmpty(sessionID) {
					removed = true
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !removed {
				t.Error("pinned owner crash left its private engine files")
			}
			if conn, err := net.DialTimeout("tcp", plan.Listen.String(), 100*time.Millisecond); err == nil {
				_ = conn.Close()
				t.Error("pinned engine survived exact owner crash")
			}
			_ = reportRead.Close()
		})
	}
	t.Cleanup(cleanup)
	request := backend.GuardianStart{Version: 1, Plan: plan, Limits: backend.Limits{StartupTimeout: 5 * time.Second, Lifetime: 15 * time.Second, StopGrace: 200 * time.Millisecond}}
	data, _ := json.Marshal(request)
	if controlWrite.SetWriteDeadline(time.Now().Add(2*time.Second)) != nil {
		t.Fatal("private owner write deadline unavailable")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	if _, err := controlWrite.Write(append(header[:], data...)); err != nil {
		t.Fatal("private owner plan handoff failed")
	}
	if reportRead.SetReadDeadline(time.Now().Add(6*time.Second)) != nil {
		t.Fatal("private owner read deadline unavailable")
	}
	if _, err := io.ReadFull(reportRead, header[:]); err != nil {
		t.Fatal("private owner readiness missing")
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > 32768 {
		t.Fatal("unbounded private owner report")
	}
	data = make([]byte, int(length))
	if _, err := io.ReadFull(reportRead, data); err != nil {
		t.Fatal("private owner report incomplete")
	}
	var report backend.OwnerProbeReport
	if json.Unmarshal(data, &report) != nil || report.Version != 1 || report.Phase != "ready" || report.Status.State != backend.Ready ||
		report.Status.Engine != plan.Engine || report.Status.CleanupOK || !report.Status.LeaseExpiresAt.After(time.Now()) || report.SessionID <= 1 {
		t.Fatal("private owner did not authenticate the pinned engine")
	}
	expectedRoot, err := filepath.EvalSymlinks(directory)
	observedRoot, observedErr := filepath.EvalSymlinks(report.Directory)
	if err != nil || observedErr != nil || filepath.Dir(observedRoot) != expectedRoot || !strings.HasPrefix(filepath.Base(observedRoot), "zarp-guardian-") {
		t.Fatal("private owner recovery root outside its fixture")
	}
	root = observedRoot
	sessionID = report.SessionID
	// Cancel only our anonymous input. Traffic and crash injection remain in
	// the sole cleanup path, without a concurrent waiter/signal race.
	stopContext := context.AfterFunc(ctx, func() { _ = controlWrite.Close() })
	t.Cleanup(func() { stopContext() })
	return cleanup
}
