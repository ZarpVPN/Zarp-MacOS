package warp

import (
	"github.com/feg55/zarp-macos/zarpd/internal/socketopts"
	"syscall"
)

// Preserve the WARP TCP/UDP interface while sharing private socket operations
// with the separate outer relay. No socket ownership is transferred here.
func getTTL(conn syscall.Conn, v6 bool) (int, error)   { return socketopts.HopLimit(conn, v6) }
func setTTL(conn syscall.Conn, v6 bool, ttl int) error { return socketopts.SetHopLimit(conn, v6, ttl) }
