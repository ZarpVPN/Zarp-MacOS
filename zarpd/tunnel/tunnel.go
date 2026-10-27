// Package tunnel pumps packets between a real macOS utun device and a warp.Session's CONNECT-IP
// stream directly — no userspace netstack, no local SOCKS5 proxy (see docs/ARCHITECTURE.md §3
// for why Android's zarpcore.Tunnel does something different and why that doesn't apply here).
package tunnel

import (
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/feg55/zarp-macos/zarpd/warp"
)

// headroom matches wireguard-go's tun_darwin.go contract: both Read and Write
// need 4 bytes before the IP packet for the kernel's/our own address-family header.
const headroom = 4

// A blocking device can occasionally return no packets, but it must make progress.
// Bound empty reads and yield so a failed device cannot consume a CPU indefinitely.
const maxEmptyReads = 100

type packetStream interface {
	ReadPacketZeroCopy(bool) ([]byte, error)
	WritePacketBuffer([]byte, int, int) ([]byte, error)
}

// Pump moves packets between dev and session in both directions until either side stops (the
// device closes, the session fails, or ctx-like cancellation happens via closing one of them
// from the caller). It blocks; run it in a goroutine and Close the Tunnel's pieces to stop it.
type Pump struct {
	dev            tun.Device
	packets        packetStream
	mtu            int
	tcpPacketLimit int
	session        *warp.Session

	errs    chan error
	stop    chan struct{}
	workers sync.WaitGroup
}

// New wraps an already-open device and an already-connected session. Neither is started or
// closed by New; the caller owns both lifetimes (mirrors Zarp-Android's Tunnel.maintain, which
// re-dials on reconnect without recreating the device — same shape expected here later).
func New(dev tun.Device, session *warp.Session, mtu int) *Pump {
	return &Pump{dev: dev, packets: session.IPConn, mtu: mtu, tcpPacketLimit: session.TCPPacketLimit, session: session, errs: make(chan error, 2), stop: make(chan struct{})}
}

// Run starts both pump directions and blocks until one of them fails. The returned error is
// whichever side failed first; the caller is responsible for tearing down dev/session afterward.
func (p *Pump) Run() error {
	defer close(p.stop)
	p.workers.Add(2)
	go func() { defer p.workers.Done(); p.pumpDeviceToSession() }()
	go func() { defer p.workers.Done(); p.pumpSessionToDevice() }()
	return <-p.errs
}

func (p *Pump) stopped() bool {
	select {
	case <-p.stop:
		return true
	default:
		return false
	}
}

// deviceWriter writes IP packets into the utun from one goroutine, reusing its scratch buffer
// (the device needs the packet behind a 4-byte header, so a copy is unavoidable — allocating a
// fresh one per packet is not).
type deviceWriter struct {
	dev  tun.Device
	buf  []byte
	bufs [][]byte
}

func newDeviceWriter(dev tun.Device, mtu int) *deviceWriter {
	return &deviceWriter{dev: dev, buf: make([]byte, headroom+mtu+64), bufs: make([][]byte, 1)}
}

func (w *deviceWriter) write(pkt []byte) error {
	need := headroom + len(pkt)
	if need > cap(w.buf) {
		w.buf = make([]byte, need)
	}
	buf := w.buf[:need]
	copy(buf[headroom:], pkt)
	w.bufs[0] = buf
	n, err := w.dev.Write(w.bufs, headroom)
	if err == nil && n != 1 {
		return errors.New("short write to utun")
	}
	return err
}

// pumpDeviceToSession reads packets the kernel routes into the utun and forwards them into the
// MASQUE session.
func (p *Pump) pumpDeviceToSession() {
	bufs := make([][]byte, 1)
	bufs[0] = make([]byte, headroom+p.mtu+64) // slack for any header growth
	sizes := make([]int, 1)
	// ICMP errors the session wants delivered back to the local stack (packet too big, ...) are
	// written from this goroutine, so they get their own writer — the other direction has one too.
	icmpOut := newDeviceWriter(p.dev, p.mtu)
	emptyReads := 0
	for {
		if p.stopped() {
			return
		}
		n, err := p.dev.Read(bufs, sizes, headroom)
		if p.stopped() {
			return
		}
		if err != nil {
			p.errs <- fmt.Errorf("utun read: %w", err)
			return
		}
		if n < 0 || n > len(bufs) {
			p.errs <- errors.New("utun read: invalid packet batch count")
			return
		}
		if n == 0 {
			emptyReads++
			if emptyReads >= maxEmptyReads {
				p.errs <- fmt.Errorf("utun read: %w", io.ErrNoProgress)
				return
			}
			timer := time.NewTimer(time.Millisecond)
			select {
			case <-p.stop:
				timer.Stop()
				return
			case <-timer.C:
			}
			continue
		}
		emptyReads = 0
		for i := 0; i < n; i++ {
			if sizes[i] <= 0 || sizes[i] > len(bufs[i])-headroom {
				p.errs <- errors.New("utun read: invalid packet size")
				return
			}
			if clampTCPMSS(bufs[i][headroom:headroom+sizes[i]], p.tcpPacketLimit) && p.session != nil {
				p.session.NoteMSSClamp(false)
			}
			icmp, err := p.packets.WritePacketBuffer(bufs[i], headroom, sizes[i])
			if err != nil {
				p.errs <- fmt.Errorf("connect-ip write: %w", err)
				return
			}
			if len(icmp) > 0 {
				if p.session != nil {
					p.session.NotePacketTooBig()
				}
				if werr := icmpOut.write(icmp); werr != nil {
					log.Printf("tunnel: writing ICMP response to utun: %v", werr)
				}
			}
		}
	}
}

// pumpSessionToDevice reads packets the MASQUE session delivers (real internet traffic coming
// back through WARP) and writes them into the utun so the kernel delivers them locally.
func (p *Pump) pumpSessionToDevice() {
	out := newDeviceWriter(p.dev, p.mtu)
	for {
		if p.stopped() {
			return
		}
		pkt, err := p.packets.ReadPacketZeroCopy(true)
		if p.stopped() {
			return
		}
		if err != nil {
			p.errs <- fmt.Errorf("connect-ip read: %w", err)
			return
		}
		if len(pkt) == 0 {
			p.errs <- fmt.Errorf("connect-ip read: %w", io.ErrNoProgress)
			return
		}
		if clampTCPMSS(pkt, p.tcpPacketLimit) && p.session != nil {
			p.session.NoteMSSClamp(true)
		}
		if err := out.write(pkt); err != nil {
			p.errs <- fmt.Errorf("utun write: %w", err)
			return
		}
	}
}
