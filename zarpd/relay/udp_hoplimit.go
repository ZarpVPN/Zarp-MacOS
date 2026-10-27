package relay

import (
	"errors"
	"io"
	"net"

	"github.com/feg55/zarp-macos/zarpd/internal/socketopts"
)

// The association's sole upstream writer calls this before any real datagram.
// An unknown/default, set, write or restore failure ends the association. The
// caller closes that exact socket and never sends real traffic with a fake TTL.
func sendFakeDatagram(conn *net.UDPConn, ipv6 bool, payload []byte, limit int) error {
	return sendFakeWithHopLimit(payload, limit, ipv6,
		func() (int, error) { return socketopts.HopLimit(conn, ipv6) },
		func(value int) error { return socketopts.SetHopLimit(conn, ipv6, value) }, conn.Write)
}

func sendFakeWithHopLimit(payload []byte, limit int, ipv6 bool, get func() (int, error), set func(int) error, write func([]byte) (int, error)) (returned error) {
	if limit < 0 || limit > 255 {
		return errors.New("invalid fake hop limit")
	}
	if limit > 0 {
		normal, err := get()
		if err != nil {
			return err
		}
		// Darwin IPv6 uses -1 for the inherited kernel default. Restoring
		// that sentinel preserves policy; replacing it with 64 would not.
		if (normal < 1 || normal > 255) && !(ipv6 && normal == -1) {
			return errors.New("unknown original hop limit")
		}
		// Also attempt restoration if applying the temporary value reports an
		// error. Restoration failure is retained alongside any write error.
		defer func() { returned = errors.Join(returned, set(normal)) }()
		if err := set(limit); err != nil {
			return err
		}
	}
	n, err := write(payload)
	if err != nil {
		return err
	}
	if n != len(payload) {
		return io.ErrShortWrite
	}
	return nil
}
