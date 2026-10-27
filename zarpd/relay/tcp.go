package relay

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

// TCPConfig fixes a single loopback server for the lifetime of this PoC relay. It is not
// an IPC request, and production physical-interface binding is not implemented here.
type TCPConfig struct {
	Target     netip.AddrPort
	ServerName string
	Username   string
	Password   string
	Lifetime   time.Duration
	Observe    func(Hello, []int)
}

type TCPRelay struct {
	cfg      TCPConfig
	listener net.Listener
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	done     chan struct{}
}

func StartTCP(ctx context.Context, cfg TCPConfig) (*TCPRelay, error) {
	if !cfg.Target.IsValid() || !cfg.Target.Addr().IsLoopback() || cfg.Target.Port() == 0 ||
		cfg.ServerName == "" || len(cfg.ServerName) > 253 || len(cfg.Username) == 0 || len(cfg.Username) > 255 ||
		len(cfg.Password) == 0 || len(cfg.Password) > 255 || cfg.Lifetime <= 0 || cfg.Lifetime > time.Minute {
		return nil, errors.New("invalid loopback relay configuration")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	r := &TCPRelay{cfg: cfg, listener: listener, ctx: ctx, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(r.done)
		stop := context.AfterFunc(ctx, func() { listener.Close() })
		defer stop()
		defer listener.Close()
		limit := make(chan struct{}, 16)
		for {
			conn, err := listener.Accept()
			if err != nil {
				break
			}
			select {
			case limit <- struct{}{}:
			default:
				conn.Close()
				continue
			}
			r.wg.Add(1)
			go func() { defer r.wg.Done(); defer func() { <-limit }(); r.serve(conn) }()
		}
		r.wg.Wait()
	}()
	return r, nil
}

func (r *TCPRelay) Address() string { return r.listener.Addr().String() }
func (r *TCPRelay) Close()          { r.cancel(); <-r.done }

func (r *TCPRelay) CloseBounded(ctx context.Context) error {
	r.cancel()
	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func writeAll(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func (r *TCPRelay) serve(client net.Conn) {
	defer client.Close()
	stop := context.AfterFunc(r.ctx, func() { client.Close() })
	defer stop()
	_ = client.SetDeadline(time.Now().Add(r.cfg.Lifetime))
	if !authenticate(client, r.cfg.Username, r.cfg.Password) {
		return
	}
	var request [4]byte
	if _, err := io.ReadFull(client, request[:]); err != nil {
		return
	}
	if request[0] != 5 || request[1] != 1 || request[2] != 0 {
		return
	}
	target, err := readAddress(client, request[3])
	if err != nil || target != r.cfg.Target {
		_ = writeAll(client, []byte{5, 2, 0, 1, 127, 0, 0, 1, 0, 0})
		return
	}
	upstream, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(r.ctx, "tcp", r.cfg.Target.String())
	if err != nil {
		return
	}
	defer upstream.Close()
	stopUpstream := context.AfterFunc(r.ctx, func() { upstream.Close() })
	defer stopUpstream()
	_ = upstream.SetDeadline(time.Now().Add(r.cfg.Lifetime))
	if tcp, ok := upstream.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
	if err := writeAll(client, []byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}
	hello, err := ReadClientHello(client)
	if err != nil || hello.ServerName != r.cfg.ServerName {
		return
	}
	// The numeric byte and mapped host offset refer to the OUTER handshake. Host can span
	// TLS records; the mapping preserves every original byte instead of rebuilding TLS.
	positions := []int{1, hello.HostOffset, len(hello.Wire)}
	if hello.HostOffset <= 1 || hello.HostOffset >= len(hello.Wire) {
		return
	}
	var lengths []int
	previous := 0
	for _, next := range positions {
		if err := writeAll(upstream, hello.Wire[previous:next]); err != nil {
			return
		}
		lengths = append(lengths, next-previous)
		previous = next
	}
	if r.cfg.Observe != nil {
		r.cfg.Observe(hello, lengths)
	}
	// Counters prove successful stream writes. Exact kernel packet boundaries and DPI effect
	// remain separate capture/manual checks; no claim of reverse-order TCP is made.
	finished := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, client); finished <- struct{}{} }()
	go func() { _, _ = io.Copy(client, upstream); finished <- struct{}{} }()
	<-finished
	client.Close()
	upstream.Close()
	<-finished
}

func authenticate(conn net.Conn, username, password string) bool {
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil || greeting[0] != 5 || greeting[1] == 0 {
		return false
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return false
	}
	if !bytes.Contains(methods, []byte{2}) {
		_ = writeAll(conn, []byte{5, 255})
		return false
	}
	if writeAll(conn, []byte{5, 2}) != nil {
		return false
	}
	var auth [2]byte
	if _, err := io.ReadFull(conn, auth[:]); err != nil || auth[0] != 1 || auth[1] == 0 {
		return false
	}
	user := make([]byte, int(auth[1]))
	if _, err := io.ReadFull(conn, user); err != nil {
		return false
	}
	var count [1]byte
	if _, err := io.ReadFull(conn, count[:]); err != nil || count[0] == 0 {
		return false
	}
	pass := make([]byte, int(count[0]))
	if _, err := io.ReadFull(conn, pass); err != nil {
		return false
	}
	valid := subtle.ConstantTimeCompare(user, []byte(username)) == 1 && subtle.ConstantTimeCompare(pass, []byte(password)) == 1
	status := byte(1)
	if valid {
		status = 0
	}
	if writeAll(conn, []byte{1, status}) != nil {
		return false
	}
	return valid
}

func readAddress(reader io.Reader, kind byte) (netip.AddrPort, error) {
	n := 4
	if kind == 4 {
		n = 16
	} else if kind != 1 {
		return netip.AddrPort{}, errors.New("numeric target required")
	}
	data := make([]byte, n+2)
	if _, err := io.ReadFull(reader, data); err != nil {
		return netip.AddrPort{}, err
	}
	address, ok := netip.AddrFromSlice(data[:n])
	if !ok {
		return netip.AddrPort{}, errors.New("invalid numeric target")
	}
	return netip.AddrPortFrom(address.Unmap(), binary.BigEndian.Uint16(data[n:])), nil
}
