// Package tunproxy forwards caller-owned IP packets through a private SOCKS
// backend. Construction is pure userspace; only its caller can create a utun.
package tunproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// Flow preserves the original application's socket tuple across userspace forwarding.
type Flow struct {
	Network             string
	Source, Destination netip.AddrPort
}

type FlowDialer interface {
	DialFlow(context.Context, Flow) (net.Conn, error)
}
type Device interface {
	Read([][]byte, []int, int) (int, error)
	Write([][]byte, int) (int, error)
}

type Bridge struct {
	ctx     context.Context
	cancel  context.CancelFunc
	stack   *stack.Stack
	link    *channel.Endpoint
	dialer  Dialer
	mtu     int
	mu      sync.Mutex
	closed  bool
	flows   sync.WaitGroup
	packets sync.WaitGroup
	limit   chan struct{}
	once    sync.Once
}

func New(parent context.Context, dialer Dialer, mtu int) (*Bridge, error) {
	if dialer == nil || mtu < 1280 || mtu > 9000 {
		return nil, errors.New("invalid private tunnel bridge")
	}
	ctx, cancel := context.WithCancel(parent)
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6}})
	ep := channel.New(512, uint32(mtu), "")
	b := &Bridge{ctx: ctx, cancel: cancel, stack: s, link: ep, dialer: dialer, mtu: mtu, limit: make(chan struct{}, 256)}
	fail := func() (*Bridge, error) { b.Stop(); return nil, errors.New("private tunnel stack configuration failed") }
	if s.CreateNIC(1, ep) != nil || s.SetPromiscuousMode(1, true) != nil || s.SetSpoofing(1, true) != nil {
		return fail()
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}, {Destination: header.IPv6EmptySubnet, NIC: 1}})
	sack := tcpip.TCPSACKEnabled(true)
	if s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack) != nil {
		return fail()
	}
	tcpForwarder := tcp.NewForwarder(s, 0, 256, func(request *tcp.ForwarderRequest) {
		id := request.ID()
		if !b.admit() {
			request.Complete(true)
			return
		}
		go func() {
			defer b.release()
			var queue waiter.Queue
			endpoint, err := request.CreateEndpoint(&queue)
			if err != nil {
				request.Complete(true)
				return
			}
			request.Complete(false)
			local := gonet.NewTCPConn(&queue, endpoint)
			b.forward(local, "tcp", id)
		}()
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	// Create the endpoint synchronously from the dispatcher's borrowed packet.
	// This avoids retaining an extra cloned first datagram for every UDP flow.
	s.SetTransportProtocolHandler(udp.ProtocolNumber, func(id stack.TransportEndpointID, packet *stack.PacketBuffer) bool {
		if !b.admit() {
			return false
		}
		var queue waiter.Queue
		endpoint, err := udp.NewForwarderRequest(s, id, packet).CreateEndpoint(&queue)
		if err != nil {
			b.release()
			return false
		}
		local := gonet.NewUDPConn(&queue, endpoint)
		go func() { defer b.release(); b.forward(local, "udp", id) }()
		return true
	})
	return b, nil
}

func (b *Bridge) admit() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return false
	}
	select {
	case b.limit <- struct{}{}:
		b.flows.Add(1)
		return true
	default:
		return false
	}
}
func (b *Bridge) release() { <-b.limit; b.flows.Done() }

func (b *Bridge) forward(local net.Conn, network string, id stack.TransportEndpointID) {
	defer local.Close()
	stopLocal := context.AfterFunc(b.ctx, func() { local.Close() })
	defer stopLocal()
	ip, ok := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	if !ok || ip.IsUnspecified() || ip.IsMulticast() {
		return
	}
	destination := netip.AddrPortFrom(ip.Unmap(), id.LocalPort)
	var remote net.Conn
	var err error
	if policy, ok := b.dialer.(FlowDialer); ok {
		source, valid := netip.AddrFromSlice(id.RemoteAddress.AsSlice())
		if !valid {
			return
		}
		remote, err = policy.DialFlow(b.ctx, Flow{Network: network, Source: netip.AddrPortFrom(source.Unmap(), id.RemotePort), Destination: destination})
	} else {
		remote, err = b.dialer.DialContext(b.ctx, network, destination.String())
	}
	if err != nil {
		return
	}
	defer remote.Close()
	stopRemote := context.AfterFunc(b.ctx, func() { remote.Close() })
	defer stopRemote()
	finished := make(chan struct{}, 2)
	copyFlow := func(dst, src net.Conn) {
		if network == "tcp" {
			_, _ = io.Copy(dst, src)
		} else {
			buffer := make([]byte, 65535)
			for {
				_ = src.SetReadDeadline(time.Now().Add(2 * time.Minute))
				n, err := src.Read(buffer)
				if err != nil {
					break
				}
				if _, err = dst.Write(buffer[:n]); err != nil {
					break
				}
			}
		}
		finished <- struct{}{}
	}
	go copyFlow(local, remote)
	go copyFlow(remote, local)
	<-finished
	local.Close()
	remote.Close()
	<-finished
}

// Run blocks until packet I/O or cancellation fails. The owner closes its
// device before Wait to release any pending device Read, just as WARP's pump does.
func (b *Bridge) Run(device Device) error {
	failed := make(chan error, 2)
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return context.Canceled
	}
	b.packets.Add(2)
	b.mu.Unlock()
	go func() {
		defer b.packets.Done()
		bufs := [][]byte{make([]byte, b.mtu+68)}
		sizes := make([]int, 1)
		for {
			n, err := device.Read(bufs, sizes, 4)
			if err != nil {
				failed <- errors.New("private tunnel read stopped")
				return
			}
			if n != 1 || sizes[0] < 1 || sizes[0] > len(bufs[0])-4 {
				failed <- errors.New("invalid private tunnel packet")
				return
			}
			packet := append([]byte(nil), bufs[0][4:4+sizes[0]]...)
			if err = b.Inject(packet); err != nil {
				continue
			}
		}
	}()
	go func() {
		defer b.packets.Done()
		for {
			packet, err := b.ReadPacket(b.ctx)
			if err != nil {
				failed <- err
				return
			}
			buf := make([]byte, len(packet)+4)
			copy(buf[4:], packet)
			if n, err := device.Write([][]byte{buf}, 4); err != nil || n != 1 {
				failed <- errors.New("private tunnel write stopped")
				return
			}
		}
	}()
	select {
	case err := <-failed:
		return err
	case <-b.ctx.Done():
		return b.ctx.Err()
	}
}

// Inject and ReadPacket also support an in-memory peer for safe protocol tests.
func (b *Bridge) Inject(data []byte) error {
	if len(data) == 0 || len(data) > b.mtu {
		return errors.New("invalid IP packet")
	}
	var protocol tcpip.NetworkProtocolNumber
	switch data[0] >> 4 {
	case 4:
		protocol = ipv4.ProtocolNumber
	case 6:
		protocol = ipv6.ProtocolNumber
	default:
		return errors.New("unsupported IP packet")
	}
	if b.ctx.Err() != nil {
		return b.ctx.Err()
	}
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
	defer packet.DecRef()
	b.link.InjectInbound(protocol, packet)
	return nil
}
func (b *Bridge) ReadPacket(ctx context.Context) ([]byte, error) {
	packet := b.link.ReadContext(ctx)
	if packet == nil {
		return nil, io.EOF
	}
	view := packet.ToView()
	packet.DecRef()
	defer view.Release()
	return append([]byte(nil), view.AsSlice()...), nil
}
func (b *Bridge) Stop() {
	b.once.Do(func() {
		b.mu.Lock()
		b.closed = true
		b.mu.Unlock()
		b.cancel()
		b.stack.Close()
		b.link.Close()
	})
}
func (b *Bridge) Wait() { b.packets.Wait(); b.flows.Wait(); b.stack.Wait() }
