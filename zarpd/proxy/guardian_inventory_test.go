package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func signedGuardianFixture(t *testing.T) (*GuardianLauncher, string, SignedGuardianPins) {
	t.Helper()
	s, bundle, inventory := signedFixture(t)
	data, err := os.ReadFile(filepath.Join(s.root, "sing-box"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"parity-backend-guardian", "test-engine"} {
		if err := os.WriteFile(filepath.Join(s.root, name), data, 0700); err != nil {
			t.Fatal(err)
		}
	}
	pins := SignedGuardianPins{Inventory: inventory, GuardianDigest: inventory.SingBoxDigest}
	g, err := NewSignedBundleGuardianLauncher(bundle, pins)
	if err != nil {
		t.Fatal(err)
	}
	return g, bundle, pins
}

func TestSignedGuardianPolicyIsFiniteImmutableAndRedacted(t *testing.T) {
	for _, pins := range []SignedGuardianPins{
		{}, {GuardianDigest: strings.Repeat("a", 64)},
		{Inventory: SignedInventoryPins{TeamID: "TESTTEAM01", SingBoxDigest: strings.Repeat("a", 64)}, GuardianDigest: "private-digest-secret"},
		{Inventory: SignedInventoryPins{TeamID: "private-team-secret", SingBoxDigest: strings.Repeat("a", 64)}, GuardianDigest: strings.Repeat("a", 64)},
	} {
		if _, err := NewSignedBundleGuardianLauncher("/missing.app", pins); err != (Error{InvalidInventory}) {
			t.Fatal("invalid release policy reached filesystem")
		}
		if strings.Contains(pins.String(), "secret") || strings.Contains(pins.GoString(), "secret") {
			t.Fatal("policy leaked input")
		}
	}
	g, _, pins := signedGuardianFixture(t)
	original := pins
	pins.GuardianDigest, pins.Inventory.TeamID = "private-secret", "CHANGED001"
	if !g.release || g.helper.relative != "parity-backend-guardian" || g.helper.digest != original.GuardianDigest || len(g.inventory.specs) != 1 || g.inventory.specs[SingBox].relative != "sing-box" {
		t.Fatal("caller mutation or arbitrary catalog changed release policy")
	}
	plan := testPlan(t, "11111111-2222-4333-a444-555555555555")
	plan.Engine, plan.Protocol, plan.Pin = Xray, VLESSTLS, strings.Repeat("01", 32)
	if _, err := g.StartLoopback(context.Background(), plan, DefaultLimits()); err != (Error{BinaryUnavailable}) {
		t.Fatal("omitted engine reached helper")
	}
	if _, err := releaseIdentifierRequirement("private-arbitrary-identifier", original.Inventory.TeamID); err != (Error{InvalidInventory}) {
		t.Fatal("arbitrary signing identifier accepted")
	}
}

func TestSignedGuardianHashPrecedesSignatureAndSignaturePrecedesExecution(t *testing.T) {
	g, _, pins := signedGuardianFixture(t)
	var checked atomic.Int32
	g.verifyHelper = func(ctx context.Context, path string, grace time.Duration) error {
		checked.Add(1)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		if info.Mode().Perm() != 0500 || hex.EncodeToString(digest[:]) != pins.GuardianDigest || filepath.Dir(path) == g.program.root {
			t.Fatal("signature checked unverified source")
		}
		entries, err := os.ReadDir(filepath.Dir(path))
		if err != nil || len(entries) != 1 {
			t.Fatal("runtime resources created before signature")
		}
		return Error{BinarySignature}
	}
	if _, err := g.StartLoopback(context.Background(), testPlan(t, "private-secret"), ownerLimits()); err != (Error{BinarySignature}) || checked.Load() != 1 {
		t.Fatal("signature refusal did not precede execution")
	}
	if err := os.WriteFile(filepath.Join(g.program.root, "parity-backend-guardian"), []byte("private-corruption"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := g.StartLoopback(context.Background(), testPlan(t, "normal"), ownerLimits()); err != (Error{BinaryIntegrity}) || checked.Load() != 1 {
		t.Fatal("hash failure reached signature verifier")
	}
	assertLauncherClean(t, os.Getenv("TMPDIR"))
}

// This is private fake-verifier wiring evidence, not signed-release acceptance.
func TestSignedGuardianApprovedFakeUsesReleaseModeAndIndependentSnapshot(t *testing.T) {
	g, _, _ := signedGuardianFixture(t)
	var checked atomic.Int32
	g.verifyHelper = func(context.Context, string, time.Duration) error {
		checked.Add(1)
		return os.WriteFile(filepath.Join(g.program.root, "parity-backend-guardian"), []byte("replacement-after-verification"), 0700)
	}
	session, err := g.StartLoopback(context.Background(), testPlan(t, "spawn-descendant"), ownerLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	if args := session.child.cmd.Args; len(args) != 2 || args[1] != "--release-session" {
		t.Fatal("release launch fell back to development mode")
	}
	if checked.Load() != 1 || session.child.cmd.Dir != g.inventory.root {
		t.Fatal("release helper/catalog selection wrong")
	}
	if err := session.Close(); err != nil || !session.Status().CleanupOK {
		t.Fatal("approved private fake failed cleanup")
	}
	if _, err := g.StartLoopback(context.Background(), testPlan(t, "normal"), ownerLimits()); err != (Error{BinaryIntegrity}) {
		t.Fatal("next launch accepted replaced source")
	}
	assertLauncherClean(t, os.Getenv("TMPDIR"))
}

func TestSignedGuardianNativeRequirementAndAdHocRefusal(t *testing.T) {
	g, bundle, pins := signedGuardianFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	requirement, err := releaseIdentifierRequirement("io.github.zarp.backend.guardian", pins.Inventory.TeamID)
	if err != nil {
		t.Fatal(err)
	}
	if err := runProbe(ctx, "/usr/bin/csreq", g.program.root, []string{"-r", requirement, "-t"}, &boundedOutput{}, 100*time.Millisecond); err != nil {
		t.Fatal("guardian requirement failed native compilation")
	}
	binary := filepath.Join(g.program.root, "parity-backend-guardian")
	if err := runProbe(ctx, "/usr/bin/codesign", g.program.root, []string{"--force", "--sign", "-", "--timestamp=none", "--identifier", "io.github.zarp.backend.guardian", "--", binary}, &boundedOutput{}, 100*time.Millisecond); err != nil {
		t.Fatal("private ad-hoc fixture signing failed")
	}
	if err := runProbe(ctx, "/usr/bin/codesign", g.program.root, []string{"--verify", "--strict", "--all-architectures", "--", binary}, &boundedOutput{}, 100*time.Millisecond); err != nil {
		t.Fatal("fixture native signature invalid")
	}
	data, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	pins.GuardianDigest = hex.EncodeToString(digest[:])
	g, err = NewSignedBundleGuardianLauncher(bundle, pins)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.StartLoopback(ctx, testPlan(t, "private-server-secret"), ownerLimits()); err != (Error{BinarySignature}) {
		t.Fatal("matching ad-hoc guardian bypassed Developer ID requirement")
	}
	cancel()
	if _, err := g.StartLoopback(ctx, testPlan(t, "normal"), ownerLimits()); err != (Error{Cancelled}) {
		t.Fatal("cancelled release launch ran code")
	}
	assertLauncherClean(t, os.Getenv("TMPDIR"))
}
