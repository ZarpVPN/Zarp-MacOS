package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/feg55/zarp-macos/zarpd/proxy"
)

// These childless fixtures inspect construction only. No guardian, engine,
// tunnel, service, signature identity or network resource is started.
func TestMain(m *testing.M) {
	if len(os.Args) == 2 && strings.HasPrefix(os.Args[1], "private-release-") {
		mode := os.Args[1]
		if mode == "private-release-pinned" || mode == "private-release-malformed" {
			releaseTeamID, releaseSingBoxDigest = "TESTTEAM01", strings.Repeat("a", 64)
		}
		if mode == "private-release-malformed" {
			releaseSingBoxDigest = "private-invalid-digest"
		}
		s, err := releaseInventory()
		expected := error(proxy.Error{Code: proxy.InvalidInventory})
		if mode == "private-release-not-leader" {
			expected = proxy.Error{Code: proxy.OwnershipUnsupported}
		}
		if mode == "private-release-pinned" {
			if err != nil || s == nil {
				os.Exit(71)
			}
		} else if err != expected || s != nil {
			os.Exit(72)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestReleaseBootstrapUsesOnlyEmbeddedPolicyAndPrivateSession(t *testing.T) {
	root := filepath.Join(t.TempDir(), "fixture.app", "Contents", "MacOS")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"empty", "pinned", "malformed", "not-leader"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "private-release-"+mode)
			cmd.Dir = root
			// Deliberately plausible runtime values must not configure the empty
			// compiled catalog. No inherited user environment is passed through.
			cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "releaseTeamID=TESTTEAM01",
				"releaseSingBoxDigest=" + strings.Repeat("b", 64), "ZARP_RELEASE_TEAM_ID=TESTTEAM01",
				"ZARP_RELEASE_SING_BOX_DIGEST=" + strings.Repeat("b", 64)}
			if mode != "not-leader" {
				cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			}
			cmd.WaitDelay = 100 * time.Millisecond
			if err := cmd.Run(); err != nil {
				t.Fatal("fixed release construction fixture failed", err)
			}
		})
	}
}
