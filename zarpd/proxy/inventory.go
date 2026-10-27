package proxy

import (
	"context"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// SignedInventoryPins are trusted release construction data. Digests must be
// calculated after final signing and embedded in the daemon's release catalog.
// Never load this policy from IPC, a profile, an unsigned manifest or the engine
// being verified. An empty digest omits that engine; at least one is required.
type SignedInventoryPins struct {
	TeamID        string
	SingBoxDigest string
	XrayDigest    string
}

func (SignedInventoryPins) String() string   { return "SignedInventoryPins(redacted)" }
func (SignedInventoryPins) GoString() string { return "SignedInventoryPins(redacted)" }

// NewSignedBundleSupervisor loads only fixed Contents/MacOS catalog members.
// Version, identifier and release certificate class cannot be supplied by an
// imported server. Digest and signature checks apply to the private snapshot,
// before the version/configuration probes can execute any engine code.
// This constructor is not wired to production activation or packaging yet.
func NewSignedBundleSupervisor(trustedBundleRoot string, pins SignedInventoryPins) (*Supervisor, error) {
	specs, err := signedEngineSpecs(pins)
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "darwin" || !strings.HasSuffix(filepath.Clean(trustedBundleRoot), ".app") {
		return nil, Error{InvalidInventory}
	}
	supervisor, err := NewSupervisor(filepath.Join(trustedBundleRoot, "Contents", "MacOS"))
	if err != nil {
		return nil, err
	}
	supervisor.specs = specs
	supervisor.verifySnapshot = func(ctx context.Context, binary string, engine Engine, grace time.Duration) error {
		return verifyReleaseSnapshot(ctx, binary, engine, pins.TeamID, grace)
	}
	return supervisor, nil
}

// NewSignedParentBundleSupervisor is a fixed guardian bootstrap. Its catalog
// comes from the signed guardian's build, never a pipe, environment or manifest.
func NewSignedParentBundleSupervisor(trustedBundleRoot string, pins SignedInventoryPins) (*Supervisor, error) {
	if !privateSessionLeader() {
		return nil, Error{OwnershipUnsupported}
	}
	s, err := NewSignedBundleSupervisor(trustedBundleRoot, pins)
	if err == nil {
		s.parentSession = true
	}
	return s, err
}

func signedEngineSpecs(pins SignedInventoryPins) (map[Engine]engineSpec, error) {
	if !validTeamID(pins.TeamID) || pins.SingBoxDigest == "" && pins.XrayDigest == "" {
		return nil, Error{InvalidInventory}
	}
	specs := make(map[Engine]engineSpec)
	for engine, digest := range map[Engine]string{SingBox: pins.SingBoxDigest, Xray: pins.XrayDigest} {
		if digest == "" {
			continue
		}
		if !validFingerprint(digest) {
			return nil, Error{InvalidInventory}
		}
		spec := pinnedEngines[engine]
		spec.relative, spec.digest = string(engine), digest
		specs[engine] = spec
	}
	return specs, nil
}

func validTeamID(team string) bool {
	if len(team) != 10 {
		return false
	}
	for _, c := range team {
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func releaseRequirement(engine Engine, team string) (string, error) {
	if !validTeamID(team) || engine != SingBox && engine != Xray {
		return "", Error{InvalidInventory}
	}
	return releaseIdentifierRequirement("io.github.zarp.backend."+string(engine), team)
}

func releaseIdentifierRequirement(identifier, team string) (string, error) {
	if !validTeamID(team) || identifier != "io.github.zarp.backend.sing-box" && identifier != "io.github.zarp.backend.xray" && identifier != "io.github.zarp.backend.guardian" {
		return "", Error{InvalidInventory}
	}
	// Apple's Developer ID CA/application OIDs exclude development, ad-hoc and
	// unrelated Apple-signed code, even if its displayed identifier is similar.
	return `=anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists` +
		` and certificate leaf[field.1.2.840.113635.100.6.1.13] exists` +
		` and certificate leaf[subject.OU] = "` + team + `"` +
		` and identifier "` + identifier + `"`, nil
}

func verifyReleaseSnapshot(ctx context.Context, binary string, engine Engine, team string, grace time.Duration) error {
	requirement, err := releaseRequirement(engine, team)
	if err != nil {
		return err
	}
	return verifyRequirementSnapshot(ctx, binary, requirement, grace)
}

func verifyRequirementSnapshot(ctx context.Context, binary, requirement string, grace time.Duration) error {
	// The absolute snapshot path cannot be interpreted as a PID. Verification
	// never signs, modifies or executes it. Raw codesign diagnostics are discarded.
	err := runProbe(ctx, "/usr/bin/codesign", filepath.Dir(binary), []string{
		"--verify", "--strict", "--all-architectures", "-R", requirement, "--", binary,
	}, &boundedOutput{}, grace)
	if err == nil || err == (Error{Cancelled}) || err == (Error{Cleanup}) {
		return err
	}
	return Error{BinarySignature}
}
