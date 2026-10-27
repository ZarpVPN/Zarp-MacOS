package proxy

import (
	"context"
	"encoding/json"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/feg55/zarp-macos/zarpd/connection"
	"golang.org/x/sys/unix"
)

type recoveryIdentity struct {
	Version int    `json:"version"`
	Engine  Engine `json:"engine"`
	Build   string `json:"build"`
}

type recoveryOwner struct {
	child     *ownedChild
	control   *os.File
	controlFD int
}

func (r *recoveryOwner) release() { _ = r.control.Close() }

func (r *recoveryOwner) identify(engine Engine, build string) bool {
	data, _ := json.Marshal(recoveryIdentity{Version: guardianVersion, Engine: engine, Build: build})
	return len(data) <= 256 && r.child.active() && writeGuardianFrame(r.controlFD, data)
}
func (r *recoveryOwner) renew() bool {
	return r.child.active() && writeGuardianFrame(r.controlFD, []byte(`{"version":1,"action":"renew"}`))
}

// startGuardianRecovery transfers only an inherited directory capability and
// private anonymous pipes. The fixed helper is the running verified snapshot.
// No imported path, PID, group, executable or argv becomes recovery authority.
func startGuardianRecovery(ctx context.Context, report *os.File, server bool) (*recoveryOwner, error) {
	if !privateSessionLeader() || !childOwnershipSupported() {
		return nil, Error{OwnershipUnsupported}
	}
	binary, err := os.Executable()
	if err != nil {
		return nil, Error{Startup}
	}
	root := filepath.Dir(binary)
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, Error{Startup}
	}
	capability := os.NewFile(uintptr(fd), "private-recovery-root")
	defer capability.Close()
	if !recoveryRootMatches(capability, root) {
		return nil, Error{InvalidControl}
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, Error{Startup}
	}
	defer reader.Close()
	ackReader, ackWriter, err := os.Pipe()
	if err != nil {
		_ = writer.Close()
		return nil, Error{Startup}
	}
	defer ackReader.Close()
	defer ackWriter.Close()
	writeFD, ackFD := int(writer.Fd()), int(ackReader.Fd())
	if !prepareGuardianPipe(writeFD, unix.O_WRONLY) || !prepareGuardianPipe(ackFD, unix.O_RDONLY) {
		_ = writer.Close()
		return nil, Error{InvalidControl}
	}
	child, err := startRecoveryChild(binary, root, []*os.File{reader, report, capability, ackWriter}, server)
	if err != nil {
		_ = writer.Close()
		return nil, Error{Startup}
	}
	_ = reader.Close()
	_ = ackWriter.Close()
	startup, stop := context.WithTimeout(ctx, 2*time.Second)
	data, err := readGuardianFrame(startup, ackFD, 128)
	stop()
	if err != nil || string(data) != `{"version":1,"phase":"armed"}` || !child.active() {
		_ = writer.Close() // Recovery, when armed, owns this session's cleanup.
		return nil, Error{ControlLost}
	}
	return &recoveryOwner{child: child, control: writer, controlFD: writeFD}, nil
}

func recoveryRootMatches(capability *os.File, root string) bool {
	if capability == nil || !filepath.IsAbs(root) || !strings.HasPrefix(filepath.Base(root), "zarp-guardian-") {
		return false
	}
	var held, named unix.Stat_t
	return unix.Fstat(int(capability.Fd()), &held) == nil && unix.Lstat(root, &named) == nil &&
		held.Mode&unix.S_IFMT == unix.S_IFDIR && held.Mode&0777 == 0700 && held.Uid == uint32(os.Geteuid()) &&
		named.Mode&unix.S_IFMT == unix.S_IFDIR && named.Dev == held.Dev && named.Ino == held.Ino && named.Uid == held.Uid
}

func decodeRecoveryIdentity(data []byte, result *recoveryIdentity) bool {
	if connection.ValidateDocumentJSON(data, 256) != nil || !exactGuardianObject(data, "version", "engine", "build") || json.Unmarshal(data, result) != nil {
		return false
	}
	spec, ok := pinnedEngines[result.Engine]
	return ok && result.Version == guardianVersion && result.Build == spec.version
}

// RunLoopbackRecovery is a fixed bootstrap for an already isolated guardian.
// A different group in the same private session reserves the original SID even
// when its leader dies. Only that original group can be signaled. The helper
// has no children, system policy, PID adoption or filesystem path input.
// A changed-group descendant prevents file cleanup and success. A separate
// detached session is outside this proof and cannot be adopted or signaled.
func RunLoopbackRecovery(control, report, capability, acknowledgement *os.File) error {
	return runRecovery(control, report, capability, acknowledgement, false)
}

func RunServerRecovery(control, report, capability, acknowledgement *os.File) error {
	return runRecovery(control, report, capability, acknowledgement, true)
}

func runRecovery(control, report, capability, acknowledgement *os.File, server bool) error {
	files := []*os.File{control, report, capability, acknowledgement}
	for _, file := range files {
		if file == nil {
			for _, other := range files {
				if other != nil {
					_ = other.Close()
				}
			}
			return Error{InvalidControl}
		}
		defer file.Close()
	}
	sid, err := recoverySession() // Derive once from kernel; no numeric input.
	root, rootErr := os.Getwd()
	controlFD, reportFD, ackFD := int(control.Fd()), int(report.Fd()), int(acknowledgement.Fd())
	if err != nil || rootErr != nil || !recoveryRootMatches(capability, root) ||
		!prepareGuardianPipe(controlFD, unix.O_RDONLY) || !prepareGuardianPipe(reportFD, unix.O_WRONLY) || !prepareGuardianPipe(ackFD, unix.O_WRONLY) {
		return Error{InvalidControl}
	}
	unix.CloseOnExec(int(capability.Fd()))
	if !writeGuardianFrame(ackFD, []byte(`{"version":1,"phase":"armed"}`)) {
		if !recoverGuardianGroup(sid, capability, root) {
			return Error{Cleanup}
		}
		return Error{ControlLost}
	}
	_ = acknowledgement.Close()
	// PoCs retain their independent cap. Product recovery uses a separate
	// renewable watchdog: a hung or dead owner cannot extend its private session.
	interrupt, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	lifetime := guardianLifetime + 5*time.Second
	if server {
		lifetime = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(interrupt, lifetime)
	data, readErr := readGuardianFrame(ctx, controlFD, 256)
	var identity recoveryIdentity
	identified := readErr == nil && decodeRecoveryIdentity(data, &identity)
	if identified {
		if server {
			cancel()
			for {
				lease, stopLease := context.WithTimeout(interrupt, time.Minute+5*time.Second)
				frame, err := readGuardianFrame(lease, controlFD, 256)
				stopLease()
				var action guardianAction
				if err != nil || !exactGuardianObject(frame, "version", "action") || connection.ValidateDocumentJSON(frame, 256) != nil ||
					json.Unmarshal(frame, &action) != nil || action.Version != guardianVersion || action.Action != "renew" {
					break
				}
			}
		} else {
			// No action or input can extend a finite loopback recovery session.
			_, _ = readGuardianFrame(ctx, controlFD, 256)
		}
	}
	cancel()
	_ = control.Close()
	clean := recoverGuardianGroup(sid, capability, root)
	if identified {
		code := ControlLost
		if !clean {
			code = Cleanup
		}
		// The daemon may have died. Failure to deliver does not undo verified
		// resource cleanup, and no unbounded output/read is attempted.
		_ = writeGuardianReport(reportFD, GuardianReport{Version: guardianVersion, Phase: "final", Code: code,
			Status: Status{Engine: identity.Engine, Version: identity.Build, State: Failed, CleanupOK: clean}, DirectChildStopped: clean})
	}
	if !clean {
		return Error{Cleanup}
	}
	return nil
}

func recoverGuardianGroup(sid int, capability *os.File, root string) bool {
	if !recoverySessionHeld(sid) {
		return false
	}
	grace := time.Now().Add(250 * time.Millisecond)
	deadline := time.Now().Add(2 * time.Second)
	termSent := false
	for time.Now().Before(deadline) {
		live, err := ownedGroupLive(sid, false)
		if err != nil {
			return false
		}
		if live == 0 {
			remaining, err := ownedSessionLiveExcept(sid, os.Getpid())
			if err != nil || remaining != 0 || !recoverySessionHeld(sid) || !recoveryRootMatches(capability, root) {
				return false
			}
			return os.RemoveAll(root) == nil
		}
		if !termSent {
			if !signalRecoverySession(sid, syscall.SIGTERM) {
				return false
			}
			termSent = true
		}
		if !time.Now().Before(grace) && !signalRecoverySession(sid, syscall.SIGKILL) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}
