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

func signedFixture(t *testing.T) (*Supervisor, string, SignedInventoryPins) {
	t.Helper()
	fake := fakeSupervisor(t)
	bundle := filepath.Join(fake.root, "release-fixture.app")
	root := filepath.Join(bundle, "Contents", "MacOS")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(fake.root, "test-engine"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sing-box"), data, 0700); err != nil {
		t.Fatal(err)
	}
	pins := SignedInventoryPins{TeamID: "TESTTEAM01", SingBoxDigest: fake.specs[SingBox].digest}
	s, err := NewSignedBundleSupervisor(bundle, pins)
	if err != nil {
		t.Fatal(err)
	}
	return s, bundle, pins
}

func TestSignedInventoryRefusesMalformedTrustedPolicy(t *testing.T) {
	for _, pins := range []SignedInventoryPins{
		{}, {TeamID: "TESTTEAM01"}, {TeamID: "private-team-secret", SingBoxDigest: strings.Repeat("a", 64)},
		{TeamID: "testteam01", SingBoxDigest: strings.Repeat("a", 64)},
		{TeamID: "TESTTEAM01", SingBoxDigest: strings.Repeat("A", 64)},
		{TeamID: "TESTTEAM01", SingBoxDigest: strings.Repeat("a", 63)},
		{TeamID: "TESTTEAM01", SingBoxDigest: strings.Repeat("a", 64), XrayDigest: "private-digest-secret"},
	} {
		if _, err := NewSignedBundleSupervisor("/nonexistent.app", pins); err != (Error{InvalidInventory}) {
			t.Fatal("malformed policy was accepted or exposed to filesystem loading")
		}
		if strings.Contains(pins.String(), "secret") || strings.Contains(pins.GoString(), "secret") {
			t.Fatal("policy diagnostics exposed input")
		}
	}
	s, _, pins := signedFixture(t)
	if _, err := NewSignedBundleSupervisor(s.root, pins); err != (Error{InvalidInventory}) {
		t.Fatal("non-bundle path was accepted")
	}
	if s.specs[SingBox].relative != "sing-box" || s.specs[SingBox].version != pinnedEngines[SingBox].version || len(s.specs) != 1 {
		t.Fatal("signed catalog accepted custom paths/versions or absent engines")
	}
	if pinnedEngines[SingBox].digest == pins.SingBoxDigest {
		t.Fatal("signed construction modified the shared development catalog")
	}
}

func TestSignatureRunsOnVerifiedSnapshotBeforeVersionAndSecretConfig(t *testing.T) {
	s, _, pins := signedFixture(t)
	var checked atomic.Int32
	s.verifySnapshot = func(ctx context.Context, path string, engine Engine, grace time.Duration) error {
		checked.Add(1)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		info, err := os.Stat(path)
		if err != nil || engine != SingBox || info.Mode().Perm() != 0500 || hex.EncodeToString(digest[:]) != pins.SingBoxDigest || filepath.Dir(path) == s.root {
			t.Fatal("signature check used unverified inventory instead of private snapshot")
		}
		if _, err := os.Stat(filepath.Join(filepath.Dir(path), "config.json")); !os.IsNotExist(err) {
			t.Fatal("credential-bearing configuration was written before signature validation")
		}
		return Error{BinarySignature}
	}
	spec := s.specs[SingBox]
	spec.versionPrefix = "deliberately-wrong-version"
	s.specs[SingBox] = spec
	if _, err := s.StartLoopback(context.Background(), testPlan(t, "private-server-secret"), DefaultLimits()); err != (Error{BinarySignature}) || checked.Load() != 1 {
		t.Fatal("version probe ran before signature refusal")
	}
}

func TestSignedInventoryDigestFailureDoesNotReachSignatureVerifier(t *testing.T) {
	s, _, _ := signedFixture(t)
	var checked atomic.Int32
	s.verifySnapshot = func(context.Context, string, Engine, time.Duration) error { checked.Add(1); return nil }
	if err := os.WriteFile(filepath.Join(s.root, "sing-box"), []byte("private-tampered-binary"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartLoopback(context.Background(), testPlan(t, "normal"), DefaultLimits()); err != (Error{BinaryIntegrity}) || checked.Load() != 0 {
		t.Fatal("tampering reached signature verification or execution")
	}
}

func TestSignedInventoryPolicyIsImmutableAndAbsentEngineCannotRun(t *testing.T) {
	s, bundle, pins := signedFixture(t)
	copyOfPins := pins
	pins.TeamID, pins.SingBoxDigest = "CHANGED001", strings.Repeat("0", 64)
	if s.specs[SingBox].digest != copyOfPins.SingBoxDigest || s.specs[SingBox].relative != "sing-box" {
		t.Fatal("caller mutation changed signed inventory")
	}
	plan := testPlan(t, "11111111-2222-4333-a444-555555555555")
	plan.Engine, plan.Protocol, plan.Pin = Xray, VLESSTLS, strings.Repeat("01", 32)
	if _, err := s.StartLoopback(context.Background(), plan, DefaultLimits()); err != (Error{BinaryUnavailable}) {
		t.Fatal("omitted engine was treated as available")
	}
	if _, err := NewSignedBundleSupervisor(bundle, SignedInventoryPins{TeamID: "TESTTEAM01", XrayDigest: strings.Repeat("a", 64)}); err != nil {
		t.Fatal("valid finite Xray-only catalog refused")
	}
}

// This tests supervisor wiring with a fake verifier, not a release signature.
func TestApprovedFakeSnapshotKeepsExecutionIndependentOfSourceReplacement(t *testing.T) {
	s, _, _ := signedFixture(t)
	s.verifySnapshot = func(ctx context.Context, path string, engine Engine, grace time.Duration) error {
		return os.WriteFile(filepath.Join(s.root, "sing-box"), []byte("replaced-after-copy"), 0700)
	}
	session, err := s.StartLoopback(context.Background(), testPlan(t, "ignore-term"), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil || !session.Status().CleanupOK {
		t.Fatal("verified snapshot runtime failed cleanup")
	}
	if _, err := s.StartLoopback(context.Background(), testPlan(t, "normal"), DefaultLimits()); err != (Error{BinaryIntegrity}) {
		t.Fatal("next run accepted replaced source")
	}
}

func TestNativeRequirementSyntaxAndAdHocReleaseRefusal(t *testing.T) {
	s, _, pins := signedFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, engine := range []Engine{SingBox, Xray} {
		requirement, err := releaseRequirement(engine, pins.TeamID)
		if err != nil {
			t.Fatal(err)
		}
		if err := runProbe(ctx, "/usr/bin/csreq", s.root, []string{"-r", requirement, "-t"}, &boundedOutput{}, 100*time.Millisecond); err != nil {
			t.Fatal("native requirement compiler refused release policy")
		}
	}
	// Re-sign only this private fake-engine fixture. No identity/keychain access,
	// production file or application is involved. The identifier matches policy,
	// but an ad-hoc signature must still fail its Apple/Developer ID/team checks.
	binary := filepath.Join(s.root, "sing-box")
	if err := runProbe(ctx, "/usr/bin/codesign", s.root, []string{
		"--force", "--sign", "-", "--timestamp=none", "--identifier", "io.github.zarp.backend.sing-box", "--", binary,
	}, &boundedOutput{}, 100*time.Millisecond); err != nil {
		t.Fatal("private ad-hoc fixture signing failed")
	}
	if err := runProbe(ctx, "/usr/bin/codesign", s.root, []string{"--verify", "--strict", "--all-architectures", "--", binary}, &boundedOutput{}, 100*time.Millisecond); err != nil {
		t.Fatal("fixture lacks a valid native ad-hoc signature")
	}
	data, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	spec := s.specs[SingBox]
	spec.digest = hex.EncodeToString(digest[:])
	s.specs[SingBox] = spec
	if _, err := s.StartLoopback(ctx, testPlan(t, "private-test-credential"), DefaultLimits()); err != (Error{BinarySignature}) {
		t.Fatal("matching native ad-hoc identifier passed release trust policy")
	}
	cancel()
	if err := verifyReleaseSnapshot(ctx, binary, SingBox, pins.TeamID, 100*time.Millisecond); err != (Error{Cancelled}) {
		t.Fatal("cancelled signature check did not stop before execution")
	}
}
