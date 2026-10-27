package proxy

import (
	"context"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type ownedChild struct {
	cmd         *exec.Cmd
	done        chan struct{}
	err         error // Written before done closes; read only afterward.
	clean       bool
	output      *boundedOutput
	stopOnce    sync.Once
	stopRequest chan time.Duration
	reaped      atomic.Bool
	isolated    bool
	ownership   sync.Mutex // Serializes the last ownership check, signal and reap.
}

type parentSessionKey struct{}

func privateSessionLeader() bool {
	pid := os.Getpid()
	group, e1 := unix.Getpgid(0)
	session, e2 := unix.Getsid(0)
	return e1 == nil && e2 == nil && group == pid && session == pid
}

func startChild(binary, dir string, args []string, output *boundedOutput) (*ownedChild, error) {
	return startChildConstructed(binary, dir, dir, args, output, nil, true)
}

func startScopedChild(ctx context.Context, binary, dir string, args []string, output *boundedOutput) (*ownedChild, error) {
	member, _ := ctx.Value(parentSessionKey{}).(bool)
	return startChildConstructed(binary, dir, dir, args, output, nil, !member)
}

func startChildConstructed(binary, working, temporary string, args []string, output *boundedOutput, extra []*os.File, isolated bool) (*ownedChild, error) {
	return startChildPlacement(binary, working, temporary, args, output, extra, isolated, false)
}

// Only the trusted guardian bootstrap can create this separate group inside
// its newly isolated session. No caller-supplied group/session ID is accepted.
func startRecoveryChild(binary, directory string, extra []*os.File, server ...bool) (*ownedChild, error) {
	argument := "--recover-session"
	if len(server) == 1 && server[0] {
		argument = "--recover-server-session"
	}
	return startChildPlacement(binary, directory, directory, []string{argument}, &boundedOutput{}, extra, false, true)
}

func startChildPlacement(binary, working, temporary string, args []string, output *boundedOutput, extra []*os.File, isolated, separateGroup bool) (*ownedChild, error) {
	if !childOwnershipSupported() {
		return nil, Error{OwnershipUnsupported}
	}
	cmd := exec.Command(binary, args...)
	if !isolated && !privateSessionLeader() {
		return nil, Error{OwnershipUnsupported}
	}
	cmd.Dir = working
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "TMPDIR=" + temporary}
	// The private session/group is created in the child before exec succeeds.
	// No inherited daemon, terminal or VPN process group can be selected.
	if isolated {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	} else if separateGroup {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}
	cmd.ExtraFiles = extra
	cmd.Stdout, cmd.Stderr = output, output
	cmd.WaitDelay = 200 * time.Millisecond
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	c := &ownedChild{cmd: cmd, done: make(chan struct{}), output: output, stopRequest: make(chan time.Duration, 1), isolated: isolated}
	go c.watch()
	return c, nil
}

func (c *ownedChild) signalGroup(signal unix.Signal) bool {
	return c.signalOwned(signal, c.isolated)
}

func (c *ownedChild) active() bool {
	c.ownership.Lock()
	defer c.ownership.Unlock()
	if c.reaped.Load() || c.cmd == nil || c.cmd.Process == nil {
		return false
	}
	exited, err := ownedChildExited(c.cmd.Process.Pid)
	return err == nil && !exited
}

func (c *ownedChild) signalLeader(signal unix.Signal) bool {
	return c.signalOwned(signal, false)
}

func (c *ownedChild) signalOwned(signal unix.Signal, group bool) bool {
	c.ownership.Lock()
	defer c.ownership.Unlock()
	// Never signal after Wait, even if a saved numeric PID/group looks valid.
	if c.reaped.Load() {
		return false
	}
	if _, err := ownedChildExited(c.cmd.Process.Pid); err != nil {
		return false
	}
	if !group {
		return c.cmd.Process.Signal(signal) == nil
	}
	err := unix.Kill(-c.cmd.Process.Pid, signal)
	return err == nil || err == unix.ESRCH
}

func (c *ownedChild) reap() error {
	c.ownership.Lock()
	defer c.ownership.Unlock()
	c.reaped.Store(true)
	return c.cmd.Wait()
}

func (c *ownedChild) watch() {
	defer close(c.done)
	pid := c.cmd.Process.Pid
	stopping := false
	var killAfter time.Time
	timer := time.NewTicker(10 * time.Millisecond)
	defer timer.Stop()
	for {
		exited, err := ownedChildExited(pid)
		if err != nil {
			// Ownership uncertainty forbids group signals. Wait only drains the
			// owned command's pipes; the unsuccessful result is never clean.
			_ = c.reap()
			c.err = Error{Cleanup}
			return
		}
		if exited || stopping {
			if exited && !c.isolated {
				// The outer owner holds the session leader and owns every member.
				// This inner command can reap only its own exact direct child.
				c.err = c.reap()
				c.clean = true
				return
			}
			live, queryErr := ownedGroupLive(pid, exited)
			if queryErr == nil && live == 0 && exited {
				remaining, sessionErr := ownedSessionLive(pid)
				if sessionErr == nil && remaining == 0 {
					// Only now may the reserved leader be reaped and its ID reused.
					c.err = c.reap()
					c.clean = true
					return
				}
				// A changed group or uncertain session is never individually
				// signaled. Keep its anchor, with bounded polling rather than spin.
				time.Sleep(100 * time.Millisecond)
				continue // The original group is empty; no group signal is useful.
			}
			if !stopping {
				stopping = true
				killAfter = time.Now().Add(200 * time.Millisecond)
				if !c.signalGroup(unix.SIGTERM) {
					c.err = Error{Cleanup}
					return
				}
			} else if !time.Now().Before(killAfter) {
				// Repeated delivery also covers forks racing the first group kill.
				if !c.signalGroup(unix.SIGKILL) {
					c.err = Error{Cleanup}
					return
				}
			}
		}
		select {
		case grace := <-c.stopRequest:
			if !stopping {
				stopping = true
				killAfter = time.Now().Add(grace)
				if !c.signalGroup(unix.SIGTERM) {
					c.err = Error{Cleanup}
					return
				}
			}
		case <-timer.C:
		}
	}
}

func (c *ownedChild) stop(grace time.Duration) bool {
	c.stopOnce.Do(func() { c.stopRequest <- grace })
	select {
	case <-c.done:
		return c.clean
	case <-time.After(grace + 2*time.Second):
		// Keep the anchor and private files if full cleanup is not verified.
		// The watcher can reap after remaining owned session members exit.
		return false
	}
}
