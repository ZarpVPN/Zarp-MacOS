package warp

import (
	"crypto/x509"
	"errors"
)

// DialError retains the failed outer-connection phase through transport wrappers.
type DialError struct {
	Phase string
	Err   error
}

func (e *DialError) Error() string { return e.Err.Error() }
func (e *DialError) Unwrap() error { return e.Err }

func atDialPhase(phase string, err error) error {
	var existing *DialError
	if errors.As(err, &existing) {
		return err
	}
	return &DialError{Phase: phase, Err: err}
}

// The pinned usque verifier distinguishes the enrolled peer key from CA trust.
// Keep verification enabled and classify only that exact rejection.
func IsPeerKeyMismatch(err error) bool {
	var invalid x509.CertificateInvalidError
	return errors.As(err, &invalid) && invalid.Detail == "remote endpoint has a different public key than what we trust in config.json"
}
