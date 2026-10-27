package warp

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestQUICStatisticsAreBoundedAndExcludePrivateErrorText(t *testing.T) {
	counters := &quicCounters{started: time.Now()}
	for i := 0; i < 1000; i++ {
		counters.packet(true, 1280, true, true)
		counters.packet(false, 1200, false, false)
	}
	session := &Session{quicStats: counters, quicCause: func() error { return fmt.Errorf("private-error-secret: %w", &quic.StatelessResetError{}) }}
	session.NoteMSSClamp(false)
	session.NoteMSSClamp(true)
	session.NotePacketTooBig()
	stats, ok := session.QUICStatistics()
	if !ok || stats.SampledTX != 256 || stats.SampledRX != 256 || stats.SentLong != 256 || stats.ReceivedShort != 256 || stats.UnexpectedPeerPackets != 256 || stats.MSSOut != 1 || stats.MSSIn != 1 || stats.PacketTooBig != 1 || stats.CloseKind != "stateless_reset" {
		t.Fatalf("unexpected bounded counters: %+v", stats)
	}
	encoded, err := json.Marshal(stats)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "private-error-secret") {
		t.Fatal("private error text escaped into statistics")
	}
	if _, ok := (&Session{}).QUICStatistics(); ok {
		t.Fatal("HTTP2 session gained QUIC observations")
	}
}

func TestQUICStatisticsCountRealSocketWritesWithoutDecoys(t *testing.T) {
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
	counters := &quicCounters{started: time.Now()}
	dst := server.LocalAddr().(*net.UDPAddr)
	conn := &initialFakeConn{UDPConn: client, endpoint: dst, steps: []FakeStep{{Blob: []byte("private-decoy"), Repeats: 3}}, flights: map[string]bool{}, stats: counters}
	packet := []byte{0xc0, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0}
	if _, _, err := conn.WriteMsgUDP(packet, nil, dst); err != nil {
		t.Fatal(err)
	}
	server.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 128)
	for i := 0; i < 4; i++ {
		if _, _, err := server.ReadFromUDP(buf); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := server.WriteToUDP([]byte("private-response"), client.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	client.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, _, _, err := conn.ReadMsgUDP(buf, make([]byte, 128)); err != nil {
		t.Fatal(err)
	}
	session := &Session{quicStats: counters}
	stats, _ := session.QUICStatistics()
	if stats.SampledTX != 1 || stats.SampledRX != 1 || stats.UnexpectedPeerPackets != 0 || stats.MaxTXBytes != len(packet) {
		t.Fatalf("decoys counted as real traffic: %+v", stats)
	}
}
