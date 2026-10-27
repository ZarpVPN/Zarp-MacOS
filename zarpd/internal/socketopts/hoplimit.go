// Package socketopts changes only the caller-owned socket. It has no interface,
// routing, DNS, firewall or process operations.
package socketopts

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func HopLimit(conn syscall.Conn, v6 bool) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var ttl int
	var serr error
	cerr := raw.Control(func(fd uintptr) {
		if v6 {
			ttl, serr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS)
		} else {
			ttl, serr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL)
		}
	})
	if cerr != nil {
		return 0, cerr
	}
	return ttl, serr
}

func SetHopLimit(conn syscall.Conn, v6 bool, ttl int) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	cerr := raw.Control(func(fd uintptr) {
		if v6 {
			serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, ttl)
		} else {
			serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, ttl)
		}
	})
	if cerr != nil {
		return cerr
	}
	return serr
}
