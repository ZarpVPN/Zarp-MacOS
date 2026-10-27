package tunnel

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// fakeDevice records what is written into it and implements just enough of tun.Device.
type fakeDevice struct {
	written [][]byte
	offsets []int
	err     error
	short   bool
}

func (d *fakeDevice) File() *os.File                         { return nil }
func (d *fakeDevice) Read([][]byte, []int, int) (int, error) { return 0, errors.New("unused") }
func (d *fakeDevice) MTU() (int, error)                      { return 1280, nil }
func (d *fakeDevice) Name() (string, error)                  { return "utun99", nil }
func (d *fakeDevice) Events() <-chan tun.Event               { return nil }
func (d *fakeDevice) Close() error                           { return nil }
func (d *fakeDevice) BatchSize() int                         { return 1 }
func (d *fakeDevice) Write(bufs [][]byte, offset int) (int, error) {
	if d.err != nil {
		return 0, d.err
	}
	if d.short {
		return 0, nil
	}
	for _, b := range bufs {
		d.written = append(d.written, append([]byte(nil), b[offset:]...))
		d.offsets = append(d.offsets, offset)
	}
	return len(bufs), nil
}

// countingDevice discards writes without recording them, so allocations can be measured.
type countingDevice struct{ fakeDevice }

func (d *countingDevice) Write(bufs [][]byte, offset int) (int, error) { return len(bufs), nil }

func TestDeviceWriterPutsThePacketBehindTheHeadroom(t *testing.T) {
	dev := &fakeDevice{}
	w := newDeviceWriter(dev, 1280)
	pkts := [][]byte{
		bytes.Repeat([]byte{0x45}, 20),
		bytes.Repeat([]byte{0x60}, 1280),
		bytes.Repeat([]byte{0x45}, 5000), // bigger than mtu+slack: the buffer grows rather than panicking
		bytes.Repeat([]byte{0x45}, 3),    // and a small one afterwards is not corrupted by the earlier large copy
	}
	for _, p := range pkts {
		if err := w.write(p); err != nil {
			t.Fatal(err)
		}
	}
	for i, p := range pkts {
		if !bytes.Equal(dev.written[i], p) || dev.offsets[i] != headroom {
			t.Fatalf("packet %d: device saw %d bytes at offset %d", i, len(dev.written[i]), dev.offsets[i])
		}
	}
}

func TestDeviceWriterDoesNotAllocatePerPacket(t *testing.T) {
	dev := &countingDevice{}
	w := newDeviceWriter(dev, 1280)
	pkt := make([]byte, 1200)
	allocs := testing.AllocsPerRun(200, func() { _ = w.write(pkt) })
	if allocs != 0 {
		t.Fatalf("%v allocations per packet written to the utun (it used to allocate a buffer for every one)", allocs)
	}
}

func TestDeviceWriterReportsFailures(t *testing.T) {
	boom := errors.New("utun gone")
	if err := newDeviceWriter(&fakeDevice{err: boom}, 1280).write([]byte{1}); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	if err := newDeviceWriter(&fakeDevice{short: true}, 1280).write([]byte{1}); err == nil {
		t.Fatal("a short write must be an error")
	}
}

// Scripted packet endpoints make the failure paths testable without an actual TUN,
// MASQUE connection, routes, DNS or daemon installation.
type readDevice struct {
	fakeDevice
	read func([][]byte, []int, int) (int, error)
}

func (d *readDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	return d.read(bufs, sizes, offset)
}

type fakePacketStream struct {
	read  func(bool) ([]byte, error)
	write func([]byte, int, int) ([]byte, error)
}

func (s *fakePacketStream) ReadPacketZeroCopy(allowAny bool) ([]byte, error) { return s.read(allowAny) }
func (s *fakePacketStream) WritePacketBuffer(data []byte, offset, size int) ([]byte, error) {
	return s.write(data, offset, size)
}
func scriptedPump(dev tun.Device, stream packetStream) *Pump {
	return &Pump{dev: dev, packets: stream, mtu: 1280, errs: make(chan error, 2), stop: make(chan struct{})}
}

func TestDevicePumpBoundsEmptyReads(t *testing.T) {
	var reads atomic.Int32
	dev := &readDevice{read: func([][]byte, []int, int) (int, error) { reads.Add(1); return 0, nil }}
	stream := &fakePacketStream{write: func([]byte, int, int) ([]byte, error) { t.Error("empty read forwarded a packet"); return nil, nil }}
	pump := scriptedPump(dev, stream)
	finished := make(chan struct{})
	go func() { defer close(finished); pump.pumpDeviceToSession() }()
	select {
	case err := <-pump.errs:
		if !errors.Is(err, io.ErrNoProgress) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		close(pump.stop)
		<-finished
		t.Fatal("empty reads kept spinning")
	}
	<-finished
	if reads.Load() <= 1 || reads.Load() > 1000 {
		t.Fatal("empty-read retry count was unbounded or rejected a transient empty read")
	}
}

func TestDevicePumpSurvivesTransientEmptyReads(t *testing.T) {
	calls := 0
	packets := [][]byte{bytes.Repeat([]byte{0x45}, 20), bytes.Repeat([]byte{0x60}, 40)}
	finished := errors.New("scripted connection ended")
	dev := &readDevice{read: func(bufs [][]byte, sizes []int, offset int) (int, error) {
		calls++
		if calls == 1 || calls == 3 {
			return 0, nil
		}
		index := (calls / 2) - 1
		copy(bufs[0][offset:], packets[index])
		sizes[0] = len(packets[index])
		return 1, nil
	}}
	forwarded := 0
	stream := &fakePacketStream{write: func(data []byte, offset, size int) ([]byte, error) {
		if !bytes.Equal(data[offset:offset+size], packets[forwarded]) {
			t.Error("packet bytes changed")
		}
		forwarded++
		if forwarded == len(packets) {
			return nil, finished
		}
		return nil, nil
	}}
	pump := scriptedPump(dev, stream)
	pump.pumpDeviceToSession()
	if err := <-pump.errs; !errors.Is(err, finished) {
		t.Fatal(err)
	}
	if forwarded != 2 || calls != 4 {
		t.Fatal("transient empty reads prevented valid packets")
	}
}

func TestDevicePumpRejectsInvalidBatchMetadata(t *testing.T) {
	for _, value := range []struct {
		name        string
		count, size int
	}{{"negative count", -1, 20}, {"excess count", 2, 20}, {"zero size", 1, 0}, {"negative size", 1, -1}, {"oversize", 1, 1 << 20}} {
		t.Run(value.name, func(t *testing.T) {
			dev := &readDevice{read: func(_ [][]byte, sizes []int, _ int) (int, error) { sizes[0] = value.size; return value.count, nil }}
			stream := &fakePacketStream{write: func([]byte, int, int) ([]byte, error) {
				t.Error("invalid metadata reached packet writer")
				return nil, nil
			}}
			pump := scriptedPump(dev, stream)
			pump.pumpDeviceToSession()
			if err := <-pump.errs; err == nil {
				t.Fatal("invalid device metadata was accepted")
			}
		})
	}
}

func TestPumpStopsEmptyReaderAfterOtherDirectionFails(t *testing.T) {
	entered := make(chan struct{})
	var once sync.Once
	var reads atomic.Int32
	dev := &readDevice{read: func([][]byte, []int, int) (int, error) {
		reads.Add(1)
		once.Do(func() { close(entered) })
		return 0, nil
	}}
	lost := errors.New("peer connection failed")
	stream := &fakePacketStream{read: func(bool) ([]byte, error) { <-entered; return nil, lost }, write: func([]byte, int, int) ([]byte, error) { return nil, nil }}
	pump := scriptedPump(dev, stream)
	if err := pump.Run(); !errors.Is(err, lost) {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { pump.workers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("peer failure left an empty-read worker running")
	}
	if reads.Load() > 1000 {
		t.Fatal("peer failure left a busy loop")
	}
}

func TestSessionPumpRejectsEmptyPackets(t *testing.T) {
	dev := &fakeDevice{}
	stream := &fakePacketStream{read: func(bool) ([]byte, error) { return nil, nil }}
	pump := scriptedPump(dev, stream)
	pump.pumpSessionToDevice()
	if err := <-pump.errs; !errors.Is(err, io.ErrNoProgress) {
		t.Fatal(err)
	}
	if len(dev.written) != 0 {
		t.Fatal("empty session packet reached device")
	}
}

func TestPumpDoesNotForwardPacketsUnblockedAfterPeerFailure(t *testing.T) {
	for _, fromDevice := range []bool{true, false} {
		t.Run(fmt.Sprint(fromDevice), func(t *testing.T) {
			var pump *Pump
			entered := make(chan struct{})
			lost := errors.New("opposite direction failed")
			var forwarded atomic.Int32
			packet := bytes.Repeat([]byte{0x45}, 20)
			dev := &readDevice{}
			stream := &fakePacketStream{write: func([]byte, int, int) ([]byte, error) { forwarded.Add(1); return nil, nil }}
			if fromDevice {
				dev.read = func(bufs [][]byte, sizes []int, offset int) (int, error) {
					close(entered)
					<-pump.stop
					copy(bufs[0][offset:], packet)
					sizes[0] = len(packet)
					return 1, nil
				}
				stream.read = func(bool) ([]byte, error) { <-entered; return nil, lost }
			} else {
				dev.read = func([][]byte, []int, int) (int, error) { <-entered; return 0, lost }
				stream.read = func(bool) ([]byte, error) { close(entered); <-pump.stop; return packet, nil }
			}
			pump = scriptedPump(dev, stream)
			if err := pump.Run(); !errors.Is(err, lost) {
				t.Fatal(err)
			}
			finished := make(chan struct{})
			go func() { pump.workers.Wait(); close(finished) }()
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Fatal("worker stayed blocked after cancellation")
			}
			if forwarded.Load() != 0 || len(dev.written) != 0 {
				t.Fatal("a late packet was forwarded after the peer failed")
			}
		})
	}
}
