//go:build !darwin || !cgo

package main

import (
	"context"
	"errors"
)

type wireCapture struct {
	packets []wirePacket
	drops   int
}

func openWireCapture(context.Context, uint16, uint16, bool) (*wireCapture, error) {
	return nil, errors.New("native capture unavailable")
}
func (c *wireCapture) stop() bool                     { return false }
func (c *wireCapture) errorCode() string              { return "capture_unsupported" }
func nativeFilterMatches([]byte, uint16, uint16) bool { return false }

func nativeFilterMatchesFamily([]byte, uint16, uint16, bool) bool { return false }
