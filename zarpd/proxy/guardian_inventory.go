package proxy

import (
	"context"
	"time"
)

// SignedGuardianPins are immutable trusted release construction data. Engines
// are signed first, their final digests are compiled into the guardian, and the
// final signed guardian digest is compiled into the daemon. No unsigned file,
// inherited environment, imported profile or control frame supplies this policy.
type SignedGuardianPins struct {
	Inventory      SignedInventoryPins
	GuardianDigest string
}

func (SignedGuardianPins) String() string   { return "SignedGuardianPins(redacted)" }
func (SignedGuardianPins) GoString() string { return "SignedGuardianPins(redacted)" }

// NewSignedBundleGuardianLauncher verifies the fixed helper's private snapshot
// before creating control pipes or executing code. It preserves the same finite
// loopback-only launcher and native ownership/recovery boundary. This does not
// activate production server IPC or certify a signed release.
func NewSignedBundleGuardianLauncher(trustedBundleRoot string, pins SignedGuardianPins) (*GuardianLauncher, error) {
	if !validFingerprint(pins.GuardianDigest) {
		return nil, Error{InvalidInventory}
	}
	inventory, err := NewSignedBundleSupervisor(trustedBundleRoot, pins.Inventory)
	if err != nil {
		return nil, err
	}
	program, err := NewSupervisor(inventory.root)
	if err != nil {
		return nil, err
	}
	requirement, err := releaseIdentifierRequirement("io.github.zarp.backend.guardian", pins.Inventory.TeamID)
	if err != nil {
		return nil, err
	}
	return &GuardianLauncher{
		program:   program,
		helper:    engineSpec{relative: "parity-backend-guardian", digest: pins.GuardianDigest},
		inventory: inventory,
		release:   true,
		verifyHelper: func(ctx context.Context, binary string, grace time.Duration) error {
			return verifyRequirementSnapshot(ctx, binary, requirement, grace)
		},
	}, nil
}
