package proxy

import (
	"context"
	"encoding/json"
	"os"

	"github.com/feg55/zarp-macos/zarpd/connection"
	"golang.org/x/sys/unix"
)

// OwnerProbeReport is private test evidence, never production IPC. The directory
// is a generated private result used only for read-only cleanup verification.
// It cannot be used for adoption, signals, binary selection or configuration.
type OwnerProbeReport struct {
	Version   int    `json:"version"`
	Phase     string `json:"phase"`
	Status    Status `json:"status"`
	Directory string `json:"directory,omitempty"`
	SessionID int    `json:"sessionId,omitempty"`
}

// ProbeSessionEmpty is read-only evidence for the private integration fixture.
// An observed numeric ID is never ownership, adoption or signal authority.
// Failed/truncated native queries cannot certify completion. A missing historical
// session means no current matching members; it does not establish ownership.
func ProbeSessionEmpty(session int) bool {
	if session <= 1 || !childOwnershipSupported() {
		return false
	}
	group, groupErr := ownedGroupLive(session, false)
	members, sessionErr := ownedSessionLive(session)
	return groupErr == nil && sessionErr == nil && group == 0 && members == 0
}

// RunLoopbackOwnerProbe lets a private parent fixture prove real engine cleanup
// after its exact owning process is killed. Bootstrap construction selects the
// trusted fixed launcher; the pipe accepts only the existing bounded loopback
// plan/limits and a fixed stop action. It owns no frontend or system resources.
func RunLoopbackOwnerProbe(parent context.Context, control, report *os.File, launcher *GuardianLauncher) error {
	if control == nil || report == nil || launcher == nil || !privateSessionLeader() {
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
	if !prepareGuardianPipe(controlFD, unix.O_RDONLY) || !prepareGuardianPipe(reportFD, unix.O_WRONLY) {
		return Error{InvalidControl}
	}
	ctx, cancel := context.WithTimeout(parent, guardianLifetime)
	defer cancel()
	data, err := readGuardianFrame(ctx, controlFD, guardianFrameLimit)
	var start GuardianStart
	if err != nil || decodeGuardianStart(data, &start) != nil || start.Ownership != "" {
		return Error{InvalidControl}
	}
	session, err := launcher.StartLoopback(ctx, start.Plan, start.Limits)
	if err != nil {
		return err
	}
	defer session.Close()
	ready, _ := json.Marshal(OwnerProbeReport{Version: guardianVersion, Phase: "ready", Status: session.Status(), Directory: session.dir, SessionID: session.child.cmd.Process.Pid})
	if !writeGuardianFrame(reportFD, ready) {
		return Error{ControlLost}
	}
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		select {
		case <-session.Done():
			cancel()
		case <-ctx.Done():
		}
	}()
	defer func() { cancel(); <-monitorDone }()
	data, err = readGuardianFrame(ctx, controlFD, 256)
	invalidControl := false
	if err == nil {
		var action guardianAction
		if connection.ValidateDocumentJSON(data, 256) != nil || !exactGuardianObject(data, "version", "action") || json.Unmarshal(data, &action) != nil || action.Version != guardianVersion || action.Action != "stop" {
			invalidControl = true
			cancel()
		}
	}
	cleanup := session.Close()
	final, _ := json.Marshal(OwnerProbeReport{Version: guardianVersion, Phase: "final", Status: session.Status()})
	_ = writeGuardianFrame(reportFD, final)
	if cleanup == nil && invalidControl {
		return Error{InvalidControl}
	}
	return cleanup
}
