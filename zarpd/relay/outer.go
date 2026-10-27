package relay

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/feg55/zarp-macos/zarpd/internal/socketopts"
	"github.com/feg55/zarp-macos/zarpd/warp"
)

// OuterConfig is trusted daemon construction data. It fixes one resolved server
// and the socket policy for every new outer flow. Imported JSON cannot set the
// dialer, interface binding, listener, credentials or plain-mode policy.
type OuterConfig struct {
	Target             netip.AddrPort
	ServerName         string
	Username, Password string
	UDP                bool
	Desync             *warp.DesyncSpec
	FakeSteps          []warp.FakeStep
	AllowPlain         bool
	Dialer             *net.Dialer
	BindUDP            func(*net.UDPConn) error
}

type OuterStatistics struct {
	Connections  uint64 `json:"connections"`
	AppliedFlows uint64 `json:"appliedFlows"`
	FakePackets  uint64 `json:"fakePackets"`
}

type Outer struct {
	cfg                         OuterConfig
	listener                    net.Listener
	ctx                         context.Context
	cancel                      context.CancelFunc
	done                        chan struct{}
	workers                     sync.WaitGroup
	connections, applied, fakes atomic.Uint64
}

func StartOuter(parent context.Context, cfg OuterConfig) (*Outer, error) {
	if !cfg.Target.IsValid() || cfg.Target.Port() == 0 || cfg.Target.Addr().IsUnspecified() || cfg.Target.Addr().IsMulticast() ||
		cfg.Target.Addr().Zone() != "" || len(cfg.Username) == 0 || len(cfg.Username) > 255 || len(cfg.Password) == 0 || len(cfg.Password) > 255 {
		return nil, errors.New("invalid outer relay configuration")
	}
	if !cfg.Target.Addr().IsLoopback() && (cfg.Dialer == nil || cfg.Dialer.Control == nil || cfg.BindUDP == nil) {
		return nil, errors.New("outer relay requires an explicit physical socket policy")
	}
	if cfg.UDP {
		if warp.ValidateFakeSteps(cfg.FakeSteps) != nil || (!cfg.AllowPlain && len(cfg.FakeSteps) == 0) || cfg.Desync != nil {
			return nil, errors.New("invalid outer UDP strategy")
		}
	} else {
		if len(cfg.FakeSteps) != 0 || (!cfg.AllowPlain && cfg.Desync == nil) {
			return nil, errors.New("invalid outer TCP strategy")
		}
		if cfg.Desync != nil {
			if len(cfg.Desync.Pos) == 0 || len(cfg.Desync.Pos) > 16 || (cfg.Desync.Mode != warp.DesyncSplit && cfg.Desync.Mode != warp.DesyncDisorder) {
				return nil, errors.New("invalid outer TCP strategy")
			}
			spec := *cfg.Desync
			spec.Pos = append([]string(nil), spec.Pos...)
			cfg.Desync = &spec
		}
	}
	steps := make([]warp.FakeStep, len(cfg.FakeSteps))
	copy(steps, cfg.FakeSteps)
	for i := range steps {
		steps[i].Blob = append([]byte(nil), steps[i].Blob...)
	}
	cfg.FakeSteps = steps
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	r := &Outer{cfg: cfg, listener: listener, ctx: ctx, cancel: cancel, done: make(chan struct{})}
	go r.run()
	return r, nil
}

func (r *Outer) Address() netip.AddrPort { return r.listener.Addr().(*net.TCPAddr).AddrPort() }
func (r *Outer) Statistics() OuterStatistics {
	return OuterStatistics{r.connections.Load(), r.applied.Load(), r.fakes.Load()}
}
func (r *Outer) CloseBounded(ctx context.Context) error {
	r.cancel()
	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (r *Outer) run() {
	defer close(r.done)
	stop := context.AfterFunc(r.ctx, func() { r.listener.Close() })
	defer stop()
	defer r.listener.Close()
	limit := make(chan struct{}, 256)
	for {
		client, err := r.listener.Accept()
		if err != nil {
			break
		}
		select {
		case limit <- struct{}{}:
		default:
			client.Close()
			continue
		}
		r.workers.Add(1)
		go func() { defer r.workers.Done(); defer func() { <-limit }(); r.serveOuter(client) }()
	}
	r.workers.Wait()
}

func (r *Outer) serveOuter(client net.Conn) {
	defer client.Close()
	stop := context.AfterFunc(r.ctx, func() { client.Close() })
	defer stop()
	_ = client.SetDeadline(time.Now().Add(15 * time.Second))
	if !authenticate(client, r.cfg.Username, r.cfg.Password) {
		return
	}
	var header [4]byte
	if _, err := io.ReadFull(client, header[:]); err != nil || header[0] != 5 || header[2] != 0 {
		return
	}
	target, err := readAddress(client, header[3])
	if err != nil {
		return
	}
	if r.cfg.UDP && header[1] == 3 && (target.Addr().IsUnspecified() || target.Addr().IsLoopback()) {
		r.serveOuterUDP(client, target)
		return
	}
	if r.cfg.UDP || header[1] != 1 || target != r.cfg.Target {
		_ = writeAll(client, []byte{5, 2, 0, 1, 127, 0, 0, 1, 0, 0})
		return
	}
	dialer := r.cfg.Dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: 10 * time.Second}
	}
	upstream, err := dialer.DialContext(r.ctx, "tcp", r.cfg.Target.String())
	if err != nil {
		return
	}
	defer upstream.Close()
	stopUpstream := context.AfterFunc(r.ctx, func() { upstream.Close() })
	defer stopUpstream()
	_ = upstream.SetDeadline(time.Now().Add(15 * time.Second))
	if writeAll(client, []byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}) != nil {
		return
	}
	r.connections.Add(1)
	if r.cfg.Desync != nil {
		hello, err := readClientHello(client, r.cfg.ServerName == "")
		if err != nil || (r.cfg.ServerName != "" && !strings.EqualFold(hello.ServerName, r.cfg.ServerName)) {
			return
		}
		positions := hello.splitPositions(r.cfg.Desync.Pos)
		if len(positions) == 0 {
			return
		} // No success credit for an unapplied strategy.
		tcp, ok := upstream.(*net.TCPConn)
		if !ok || tcp.SetNoDelay(true) != nil {
			return
		}
		previous := 0
		for i, end := range append(positions, len(hello.Wire)) {
			var err error
			if i == 0 && r.cfg.Desync.Mode == warp.DesyncDisorder {
				v6 := r.cfg.Target.Addr().Is6()
				normal, readErr := socketopts.HopLimit(tcp, v6)
				if readErr != nil || socketopts.SetHopLimit(tcp, v6, 1) != nil {
					return
				}
				err = writeAll(upstream, hello.Wire[previous:end])
				if restore := socketopts.SetHopLimit(tcp, v6, normal); err == nil {
					err = restore
				}
			} else {
				err = writeAll(upstream, hello.Wire[previous:end])
			}
			if err != nil {
				return
			}
			previous = end
			if end < len(hello.Wire) {
				time.Sleep(time.Millisecond)
			}
		}
		r.applied.Add(1)
	}
	_ = client.SetDeadline(time.Time{})
	_ = upstream.SetDeadline(time.Time{})
	copyDuplex(client, upstream)
}

func copyDuplex(a, b net.Conn) {
	finished := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(a, b); finished <- struct{}{} }()
	go func() { _, _ = io.Copy(b, a); finished <- struct{}{} }()
	<-finished
	a.Close()
	b.Close()
	<-finished
}

func (h Hello) splitPositions(spec []string) []int {
	unique := map[int]bool{}
	for _, value := range spec {
		position := -1
		switch value {
		case "host":
			position = h.HostOffset
		case "endhost":
			if len(h.hostOffsets) > 0 {
				position = h.hostOffsets[len(h.hostOffsets)-1] + 1
			}
		case "sld", "midsld":
			labels := strings.Split(h.ServerName, ".")
			if len(labels) >= 2 {
				index := len(h.ServerName) - len(labels[len(labels)-1]) - 1 - len(labels[len(labels)-2])
				if value == "midsld" {
					index += len(labels[len(labels)-2]) / 2
				}
				if index >= 0 && index < len(h.hostOffsets) {
					position = h.hostOffsets[index]
				}
			}
		default:
			if n, err := strconv.Atoi(value); err == nil {
				position = n
				if n < 0 {
					position += len(h.Wire)
				}
			}
		}
		if position > 0 && position < len(h.Wire) {
			unique[position] = true
		} else {
			return nil // Every requested split must be applicable to this handshake.
		}
	}
	result := make([]int, 0, len(unique))
	for position := range unique {
		result = append(result, position)
	}
	sort.Ints(result)
	return result
}

func (r *Outer) serveOuterUDP(control net.Conn, requested netip.AddrPort) {
	ingress, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return
	}
	defer ingress.Close()
	network := "udp4"
	if r.cfg.Target.Addr().Is6() {
		network = "udp6"
	}
	upstream, err := net.ListenUDP(network, nil)
	if err != nil {
		return
	}
	defer upstream.Close()
	if r.cfg.BindUDP != nil && r.cfg.BindUDP(upstream) != nil {
		return
	}
	ctx, cancel := context.WithCancel(r.ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { control.Close(); ingress.Close(); upstream.Close() })
	defer stop()
	reply := []byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(reply[8:], uint16(ingress.LocalAddr().(*net.UDPAddr).Port))
	if writeAll(control, reply) != nil {
		return
	}
	_ = control.SetDeadline(time.Time{})
	finished := make(chan struct{}, 3)
	go func() { _, _ = io.Copy(io.Discard, control); cancel(); finished <- struct{}{} }()
	var peer netip.AddrPort
	var mutex sync.Mutex
	go func() {
		defer func() { cancel(); finished <- struct{}{} }()
		buffer := make([]byte, 65535)
		first := true
		for {
			n, source, err := ingress.ReadFromUDPAddrPort(buffer)
			if err != nil {
				return
			}
			source = netip.AddrPortFrom(source.Addr().Unmap(), source.Port())
			if !source.Addr().IsLoopback() || requested.Port() != 0 && requested.Port() != source.Port() {
				continue
			}
			mutex.Lock()
			same := !peer.IsValid() || peer == source
			mutex.Unlock()
			if !same {
				continue
			}
			payload, ok := decodeUDP(buffer[:n], r.cfg.Target)
			if !ok {
				continue
			}
			mutex.Lock()
			peer = source
			mutex.Unlock()
			if first {
				r.connections.Add(1)
				packets, _, err := warp.SendFakes(upstream, net.UDPAddrFromAddrPort(r.cfg.Target), r.cfg.FakeSteps, nil)
				if err != nil {
					return
				}
				r.fakes.Add(uint64(packets))
				if packets > 0 {
					r.applied.Add(1)
				}
			}
			if count, err := upstream.WriteToUDPAddrPort(payload, r.cfg.Target); err != nil || count != len(payload) {
				return
			}
			first = false
		}
	}()
	go func() {
		defer func() { cancel(); finished <- struct{}{} }()
		buffer := make([]byte, 65535)
		for {
			n, source, err := upstream.ReadFromUDPAddrPort(buffer)
			if err != nil {
				return
			}
			if source != r.cfg.Target {
				continue
			}
			mutex.Lock()
			destination := peer
			mutex.Unlock()
			if destination.IsValid() {
				if _, err := ingress.WriteToUDPAddrPort(encodeUDP(r.cfg.Target, buffer[:n]), destination); err != nil {
					return
				}
			}
		}
	}()
	<-finished
	<-finished
	<-finished
}
