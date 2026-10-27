package relay

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

// UDPConfig is a loopback-only PoC. One authenticated association owns one outer socket.
// Fake is a deliberately invalid test datagram, not a claimed production desync technique.
type UDPConfig struct {
	Target             netip.AddrPort
	Username, Password string
	Lifetime           time.Duration
	Fake               []byte
	FakeHopLimit       int // 0 preserves default; 1..255 applies only to the first fake.
	Observe            func(source netip.AddrPort, fakeBytes, firstRealBytes int)
}

type UDPRelay struct {
	listener net.Listener
	cancel   context.CancelFunc
	done     chan struct{}
}

func StartUDP(parent context.Context, cfg UDPConfig) (*UDPRelay, error) {
	if !cfg.Target.IsValid() || !cfg.Target.Addr().IsLoopback() || cfg.Target.Port() == 0 || len(cfg.Username) == 0 || len(cfg.Username) > 255 || len(cfg.Password) == 0 || len(cfg.Password) > 255 || cfg.Lifetime <= 0 || cfg.Lifetime > time.Minute || len(cfg.Fake) == 0 || len(cfg.Fake) > 1200 || cfg.FakeHopLimit < 0 || cfg.FakeHopLimit > 255 {
		return nil, errors.New("invalid loopback UDP relay configuration")
	}
	cfg.Fake = append([]byte(nil), cfg.Fake...)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	relay := &UDPRelay{listener: listener, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(relay.done)
		stop := context.AfterFunc(ctx, func() { listener.Close() })
		defer stop()
		defer listener.Close()
		var workers sync.WaitGroup
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
			workers.Add(1)
			go func() { defer workers.Done(); defer func() { <-limit }(); serveUDP(ctx, conn, cfg) }()
		}
		workers.Wait()
	}()
	return relay, nil
}
func (r *UDPRelay) Address() string { return r.listener.Addr().String() }
func (r *UDPRelay) Close()          { r.cancel(); <-r.done }

func (r *UDPRelay) CloseBounded(ctx context.Context) error {
	r.cancel()
	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func serveUDP(parent context.Context, control net.Conn, cfg UDPConfig) {
	ctx, cancel := context.WithTimeout(parent, cfg.Lifetime)
	defer cancel()
	defer control.Close()
	stop := context.AfterFunc(ctx, func() { control.Close() })
	defer stop()
	_ = control.SetDeadline(time.Now().Add(cfg.Lifetime))
	if !authenticate(control, cfg.Username, cfg.Password) {
		return
	}
	var request [4]byte
	if _, err := io.ReadFull(control, request[:]); err != nil || request[0] != 5 || request[1] != 3 || request[2] != 0 {
		return
	}
	requested, err := readAddress(control, request[3])
	if err != nil || !(requested.Addr().IsUnspecified() || requested.Addr().IsLoopback()) {
		return
	}
	ingress, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return
	}
	defer ingress.Close()
	upstream, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(cfg.Target))
	if err != nil {
		return
	}
	defer upstream.Close()
	stopUDP := context.AfterFunc(ctx, func() { ingress.Close(); upstream.Close() })
	defer stopUDP()
	port := ingress.LocalAddr().(*net.UDPAddr).Port
	reply := []byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(reply[8:], uint16(port))
	if writeAll(control, reply) != nil {
		return
	}
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
			if !source.Addr().IsLoopback() || (requested.Port() != 0 && requested.Port() != source.Port()) {
				continue
			}
			mutex.Lock()
			same := !peer.IsValid() || peer == source
			mutex.Unlock()
			if !same {
				continue
			}
			payload, ok := decodeUDP(buffer[:n], cfg.Target)
			if !ok {
				continue
			}
			mutex.Lock()
			peer = source
			mutex.Unlock()
			if first {
				if err := sendFakeDatagram(upstream, cfg.Target.Addr().Is6(), cfg.Fake, cfg.FakeHopLimit); err != nil {
					return
				}
			}
			if count, err := upstream.Write(payload); err != nil || count != len(payload) {
				return
			}
			if first && cfg.Observe != nil {
				cfg.Observe(upstream.LocalAddr().(*net.UDPAddr).AddrPort(), len(cfg.Fake), len(payload))
			}
			first = false
		}
	}()
	go func() {
		defer func() { cancel(); finished <- struct{}{} }()
		buffer := make([]byte, 65535)
		for {
			n, err := upstream.Read(buffer)
			if err != nil {
				return
			}
			mutex.Lock()
			destination := peer
			mutex.Unlock()
			if !destination.IsValid() {
				continue
			}
			packet := encodeUDP(cfg.Target, buffer[:n])
			if _, err := ingress.WriteToUDPAddrPort(packet, destination); err != nil {
				return
			}
		}
	}()
	<-finished
	<-finished
	<-finished
}

func decodeUDP(packet []byte, target netip.AddrPort) ([]byte, bool) {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return nil, false
	}
	width := 4
	if packet[3] == 4 {
		width = 16
	} else if packet[3] != 1 {
		return nil, false
	}
	if len(packet) <= 4+width+2 {
		return nil, false
	}
	address, ok := netip.AddrFromSlice(packet[4 : 4+width])
	if !ok {
		return nil, false
	}
	if netip.AddrPortFrom(address.Unmap(), binary.BigEndian.Uint16(packet[4+width:])) != target {
		return nil, false
	}
	return packet[4+width+2:], true
}
func encodeUDP(target netip.AddrPort, payload []byte) []byte {
	kind := byte(1)
	if target.Addr().Is6() {
		kind = 4
	}
	packet := []byte{0, 0, 0, kind}
	packet = append(packet, target.Addr().AsSlice()...)
	packet = binary.BigEndian.AppendUint16(packet, target.Port())
	return append(packet, payload...)
}
