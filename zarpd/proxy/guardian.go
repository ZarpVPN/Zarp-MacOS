package proxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"time"

	"github.com/feg55/zarp-macos/zarpd/connection"
	"golang.org/x/sys/unix"
)

const guardianVersion = 1
const guardianFrameLimit = connection.MaxRequestBytes
const guardianPoll = 10 * time.Millisecond
const guardianLifetime = 2 * time.Minute

// GuardianStart can travel only over an exclusively inherited anonymous pipe.
// It contains no executable, argv, configuration path, TUN or system policy.
type GuardianStart struct {
	Version   int          `json:"version"`
	Plan      LoopbackPlan `json:"plan"`
	Limits    Limits       `json:"limits"`
	Ownership string       `json:"ownership,omitempty"`
	Server    *ServerPlan  `json:"server,omitempty"`
}

func (GuardianStart) String() string   { return "GuardianStart(redacted)" }
func (GuardianStart) GoString() string { return "GuardianStart(redacted)" }

type GuardianReport struct {
	Version            int    `json:"version"`
	Phase              string `json:"phase"`
	Code               Code   `json:"code,omitempty"`
	Status             Status `json:"status"`
	DirectChildStopped bool   `json:"directChildStopped,omitempty"`
}

type guardianAction struct {
	Version int    `json:"version"`
	Action  string `json:"action"`
}

// RunLoopbackGuardian takes ownership of both pipe handles. It watches the
// control writer independently of the daemon. EOF/malformed input cancels its
// exact engine child, including during startup. Only loopback plans are allowed.
// This finite PoC does not own system routes or production activation. The typed
// launcher can retain the private session leader for member cleanup. No arbitrary
// PID/process-name adoption is accepted.
func RunLoopbackGuardian(parent context.Context, control, report *os.File, supervisor *Supervisor) error {
	if control == nil || report == nil {
		if control != nil {
			_ = control.Close()
		}
		if report != nil {
			_ = report.Close()
		}
		return Error{InvalidControl}
	}
	defer control.Close()
	defer report.Close()
	controlFD, reportFD := int(control.Fd()), int(report.Fd())
	if supervisor == nil || !prepareGuardianPipe(controlFD, unix.O_RDONLY) || !prepareGuardianPipe(reportFD, unix.O_WRONLY) {
		return Error{InvalidControl}
	}
	bounded, stopBounded := context.WithCancel(parent)
	if !supervisor.serverRuntime {
		stopBounded()
		bounded, stopBounded = context.WithTimeout(parent, guardianLifetime)
	}
	defer stopBounded()
	ctx, cancel := context.WithCancelCause(bounded)
	defer cancel(nil)
	var recovery *recoveryOwner
	if supervisor.parentSession {
		var err error
		recovery, err = startGuardianRecovery(ctx, report, supervisor.serverRuntime)
		if err != nil {
			return err
		}
		defer recovery.release()
		monitorDone := make(chan struct{})
		go func() {
			defer close(monitorDone)
			select {
			case <-recovery.child.done:
				cancel(Error{ControlLost})
			case <-ctx.Done():
			}
		}()
		defer func() { cancel(nil); <-monitorDone }()
	}
	initial, stopInitial := context.WithTimeout(ctx, 15*time.Second)
	data, err := readGuardianFrame(initial, controlFD, guardianFrameLimit)
	stopInitial()
	var start GuardianStart
	if err == nil {
		err = decodeGuardianStart(data, &start)
	}
	if err == nil && (start.Ownership == "parent-session") != supervisor.parentSession {
		err = Error{InvalidControl}
	}
	if err == nil && (start.Server != nil) != supervisor.serverRuntime {
		err = Error{InvalidControl}
	}
	if err != nil {
		_ = writeGuardianReport(reportFD, GuardianReport{Version: guardianVersion, Phase: "final", Code: InvalidControl,
			Status: Status{State: Failed, CleanupOK: true}})
		return Error{InvalidControl}
	}
	if recovery != nil {
		version, available := supervisor.versionFor(start.Plan.Engine)
		if !available || !recovery.identify(start.Plan.Engine, version) {
			return Error{ControlLost}
		}
	}
	renew := make(chan struct{}, 1)
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for count := 0; count < 4096 || supervisor.serverRuntime; count++ {
			data, err := readGuardianFrame(ctx, controlFD, 256)
			if err != nil {
				code := InvalidControl
				if err == io.EOF {
					code = ControlLost
				}
				cancel(Error{code})
				return
			}
			var action guardianAction
			if !exactGuardianObject(data, "version", "action") || connection.ValidateDocumentJSON(data, 256) != nil ||
				json.Unmarshal(data, &action) != nil || action.Version != guardianVersion {
				cancel(Error{InvalidControl})
				return
			}
			switch action.Action {
			case "renew":
				select {
				case renew <- struct{}{}:
				default:
				}
			case "stop":
				cancel(Error{Cancelled})
				return
			default:
				cancel(Error{InvalidControl})
				return
			}
		}
		cancel(Error{InvalidControl})
	}()
	defer func() { cancel(nil); <-readerDone }()
	var session *Session
	if start.Server != nil {
		session, err = supervisor.StartServer(ctx, *start.Server, start.Limits)
	} else {
		session, err = supervisor.StartLoopback(ctx, start.Plan, start.Limits)
	}
	if err != nil {
		code := Startup
		if failure, ok := err.(Error); ok {
			code = failure.Code
		}
		_ = writeGuardianReport(reportFD, GuardianReport{Version: guardianVersion, Phase: "final", Code: code,
			Status: Status{Engine: start.Plan.Engine, State: Failed, CleanupOK: err != (Error{Cleanup})}})
		return err
	}
	if !writeGuardianReport(reportFD, GuardianReport{Version: guardianVersion, Phase: "ready", Status: session.Status()}) {
		cancel(Error{ControlLost})
	}
watch:
	for {
		select {
		case <-session.Done():
			break watch
		case <-ctx.Done():
			break watch
		case <-renew:
			renewErr := session.RenewLease() // Inactive leases cannot be revived.
			if renewErr == nil && supervisor.serverRuntime && recovery != nil && !recovery.renew() {
				renewErr = Error{ControlLost}
				cancel(Error{ControlLost})
			}
			if supervisor.parentSession {
				var code Code
				if renewErr != nil {
					code = Inactive
				}
				if !writeGuardianReport(reportFD, GuardianReport{Version: guardianVersion, Phase: "renewed", Code: code, Status: session.Status()}) {
					cancel(Error{ControlLost})
				}
			}
		}
	}
	cleanup := session.Close()
	status := session.Status()
	directStopped := supervisor.parentSession && session.child.clean
	if directStopped {
		// Full member and file cleanup belongs to the outer reserved leader.
		cleanup = nil
	}
	var code Code
	if cause, ok := context.Cause(ctx).(Error); ok {
		code = cause.Code
	}
	if cleanup != nil {
		code = Cleanup
	}
	if !writeGuardianReport(reportFD, GuardianReport{Version: guardianVersion, Phase: "final", Code: code, Status: status, DirectChildStopped: directStopped}) {
		if cleanup == nil {
			cleanup = Error{ControlLost}
		}
	}
	return cleanup
}

func prepareGuardianPipe(fd, access int) bool {
	var info unix.Stat_t
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != access || unix.Fstat(fd, &info) != nil ||
		info.Mode&unix.S_IFMT != unix.S_IFIFO || info.Nlink != 0 || unix.SetNonblock(fd, true) != nil {
		return false
	}
	unix.CloseOnExec(fd)
	return true
}

func decodeGuardianStart(data []byte, result *GuardianStart) error {
	if connection.ValidateDocumentJSON(data, guardianFrameLimit) != nil ||
		(!exactGuardianObject(data, "version", "plan", "limits") && !exactGuardianObject(data, "version", "plan", "limits", "ownership") && !exactGuardianObject(data, "version", "plan", "limits", "ownership", "server")) {
		return Error{InvalidControl}
	}
	var parts map[string]json.RawMessage
	_ = json.Unmarshal(data, &parts)
	if !exactGuardianObject(parts["limits"], "StartupTimeout", "Lifetime", "StopGrace") {
		return Error{InvalidControl}
	}
	var planFields map[string]json.RawMessage
	if json.Unmarshal(parts["plan"], &planFields) != nil || planFields == nil {
		return Error{InvalidControl}
	}
	allowed := map[string]bool{}
	for _, key := range []string{"Engine", "Protocol", "Target", "Relay", "Listen", "ServerName", "Pin", "Credential",
		"RelayUser", "RelayPassword", "ProbeUser", "ProbePassword", "HTTPTransport", "Path", "HostHeader", "ServiceName",
		"Flow", "Fingerprint", "RealityPublicKey", "RealityShortID", "ObfsPassword"} {
		allowed[key] = true
	}
	for key := range planFields {
		if !allowed[key] {
			return Error{InvalidControl}
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(result) != nil || result.Version != guardianVersion || !result.Limits.valid() ||
		result.Ownership != "" && result.Ownership != "parent-session" {
		return Error{InvalidControl}
	}
	if result.Server != nil {
		if result.Server.validate() != nil || result.Plan != result.Server.readiness() {
			return Error{InvalidControl}
		}
	} else if result.Plan.validate() != nil {
		return Error{InvalidControl}
	}
	return nil
}

func exactGuardianObject(data []byte, keys ...string) bool {
	var values map[string]json.RawMessage
	if json.Unmarshal(data, &values) != nil || len(values) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := values[key]; !ok {
			return false
		}
	}
	return true
}

func readGuardianFrame(ctx context.Context, fd, limit int) ([]byte, error) {
	var header [4]byte
	if err := readGuardianBytes(ctx, fd, header[:]); err != nil {
		return nil, err
	}
	count := binary.BigEndian.Uint32(header[:])
	if count == 0 || count > uint32(limit) {
		return nil, Error{InvalidControl}
	}
	data := make([]byte, int(count))
	if err := readGuardianBytes(ctx, fd, data); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return data, nil
}

func readGuardianBytes(ctx context.Context, fd int, data []byte) error {
	for offset := 0; offset < len(data); {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n, err := unix.Read(fd, data[offset:])
		if n > 0 {
			offset += n
		}
		if err == unix.EINTR {
			continue
		}
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			if !guardianPause(ctx) {
				return ctx.Err()
			}
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 {
			if offset > 0 {
				return io.ErrUnexpectedEOF
			}
			return io.EOF
		}
	}
	return nil
}

func guardianPause(ctx context.Context) bool {
	timer := time.NewTimer(guardianPoll)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func writeGuardianReport(fd int, report GuardianReport) bool {
	data, err := json.Marshal(report)
	if err != nil || len(data) > guardianFrameLimit {
		return false
	}
	return writeGuardianFrame(fd, data)
}

func writeGuardianFrame(fd int, data []byte) bool {
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	data = append(header[:], data...)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for offset := 0; offset < len(data); {
		if ctx.Err() != nil {
			return false
		}
		n, err := unix.Write(fd, data[offset:])
		if n > 0 {
			offset += n
		}
		if err == unix.EINTR {
			continue
		}
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			if !guardianPause(ctx) {
				return false
			}
			continue
		}
		if err != nil || n == 0 {
			return false
		}
	}
	return true
}
