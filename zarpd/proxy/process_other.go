//go:build !darwin || !cgo

package proxy

import "syscall"

func childOwnershipSupported() bool                  { return false }
func ownedChildExited(int) (bool, error)             { return false, Error{Cleanup} }
func ownedGroupLive(int, bool) (int, error)          { return 0, Error{Cleanup} }
func ownedSessionLive(int) (int, error)              { return 0, Error{Cleanup} }
func ownedSessionLiveExcept(int, int) (int, error)   { return 0, Error{Cleanup} }
func recoverySession() (int, error)                  { return 0, Error{OwnershipUnsupported} }
func signalRecoverySession(int, syscall.Signal) bool { return false }
func recoverySessionHeld(int) bool                   { return false }
