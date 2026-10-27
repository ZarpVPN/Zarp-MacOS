// parity-backend-guardian is an isolated loopback PoC. It never accesses
// public IPC, accounts, TUN, routes or DNS. Its inventory is the fixed
// development catalog, or final engine pins embedded in a signed release build.
// No inherited environment, pipe or unsigned manifest supplies release policy.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/feg55/zarp-macos/zarpd/proxy"
)

// Set only by trusted release build flags after final engine signing. Empty
// defaults refuse --release-session; development builds cannot fall back to
// upstream hashes when asked for release mode. No runtime setter exists.
var releaseTeamID string
var releaseSingBoxDigest string
var releaseXrayDigest string

func releaseInventory() (*proxy.Supervisor, error) {
	root, err := os.Getwd()
	if err != nil {
		return nil, proxy.Error{Code: proxy.InvalidInventory}
	}
	return proxy.NewSignedParentBundleSupervisor(filepath.Dir(filepath.Dir(root)), proxy.SignedInventoryPins{
		TeamID: releaseTeamID, SingBoxDigest: releaseSingBoxDigest, XrayDigest: releaseXrayDigest,
	})
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--owner-probe" {
		executable, err := os.Executable()
		if err != nil {
			os.Exit(2)
		}
		data, err := os.ReadFile(executable)
		if err != nil || len(data) > 64<<20 {
			os.Exit(2)
		}
		digest := sha256.Sum256(data)
		launcher, err := proxy.NewLoopbackGuardianLauncher(filepath.Dir(executable), hex.EncodeToString(digest[:]), ".")
		if err != nil {
			os.Exit(2)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if proxy.RunLoopbackOwnerProbe(ctx, os.NewFile(3, "owner-probe-control"), os.NewFile(4, "owner-probe-report"), launcher) != nil {
			os.Exit(2)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--recover-session" {
		if proxy.RunLoopbackRecovery(os.NewFile(3, "recovery-control"), os.NewFile(4, "recovery-report"),
			os.NewFile(5, "recovery-root"), os.NewFile(6, "recovery-ack")) != nil {
			os.Exit(2)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--recover-server-session" {
		if proxy.RunServerRecovery(os.NewFile(3, "recovery-control"), os.NewFile(4, "recovery-report"),
			os.NewFile(5, "recovery-root"), os.NewFile(6, "recovery-ack")) != nil {
			os.Exit(2)
		}
		return
	}
	member := len(os.Args) == 2 && os.Args[1] == "--owned-session"
	release := len(os.Args) == 2 && os.Args[1] == "--release-session"
	server := len(os.Args) == 2 && os.Args[1] == "--server-session"
	if len(os.Args) != 1 && !member && !release && !server {
		os.Exit(2)
	}
	supervisor, err := proxy.NewSupervisor(".")
	if member {
		supervisor, err = proxy.NewParentSessionSupervisor(".")
	}
	if release {
		supervisor, err = releaseInventory()
	}
	if server {
		supervisor, err = proxy.NewParentServerSupervisor(".")
	}
	if err != nil {
		os.Exit(2)
	}
	control := os.NewFile(3, "guardian-control")
	report := os.NewFile(4, "guardian-report")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if proxy.RunLoopbackGuardian(ctx, control, report, supervisor) != nil {
		os.Exit(2)
	}
}
