package warp

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
)

func TestInitialFakeRetriesAreDeduplicatedAndBounded(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	dst := server.LocalAddr().(*net.UDPAddr)
	var reports []FakeReport
	conn := &initialFakeConn{UDPConn: client, endpoint: dst, flights: map[string]bool{},
		steps:     []FakeStep{{Blob: []byte("private-decoy"), Repeats: 1, TTL: 7}},
		onApplied: func(report FakeReport) { reports = append(reports, report) }}
	before, err := getTTL(client, false)
	if err != nil {
		t.Fatal(err)
	}
	packet := []byte{0xc0, 0, 0, 0, 1, 8, 0, 0, 0, 0, 0, 0, 0, 1, 0}
	for _, id := range []byte{1, 1, 2, 3, 4} {
		packet[13] = id
		if _, _, err := conn.WriteMsgUDP(packet, nil, dst); err != nil {
			t.Fatal(err)
		}
	}
	packet[13] = 5
	if _, _, err := conn.WriteMsgUDP(packet, nil, dst); err == nil {
		t.Fatal("unbounded new Initial flights were allowed")
	}
	after, err := getTTL(client, false)
	if err != nil || after != before {
		t.Fatalf("real packet TTL changed: %d to %d: %v", before, after, err)
	}
	if len(reports) != 4 {
		t.Fatalf("got %d fake bursts for four new CIDs", len(reports))
	}
	for i, report := range reports {
		if report.Flight != i+1 || report.Packets != 1 {
			t.Fatalf("unexpected fake counts: %+v", report)
		}
	}
	server.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 256)
	fakes, real := 0, 0
	for {
		n, _, err := server.ReadFromUDP(buf)
		if err != nil {
			var ne net.Error
			if !errors.As(err, &ne) || !ne.Timeout() {
				t.Fatal(err)
			}
			break
		}
		if bytes.Equal(buf[:n], []byte("private-decoy")) {
			fakes++
		} else {
			real++
		}
	}
	if fakes != 4 || real != 5 {
		t.Fatalf("wire counts: %d fakes, %d Initial packets", fakes, real)
	}
}
