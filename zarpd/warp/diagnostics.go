package warp

import (
	"errors"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// QUICStatistics contains bounded numeric observations only. Packet bytes,
// connection IDs, reset tokens, hostnames and TLS secrets are never retained.
type QUICStatistics struct {
	SampledTX, SampledRX                             int
	MaxTXBytes, MaxRXBytes                           int
	SentLong, SentShort, ReceivedLong, ReceivedShort int
	UnexpectedPeerPackets                            int
	MSSOut, MSSIn, PacketTooBig                      uint64
	ElapsedMs                                        int64
	CloseKind                                        string
}

const maxQUICPacketSamples = 256

type quicCounters struct {
	mu      sync.Mutex
	started time.Time
	value   QUICStatistics
}

func (c *quicCounters) packet(sent bool, size int, long, expectedPeer bool) {
	if c == nil || size <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if sent {
		if c.value.SampledTX >= maxQUICPacketSamples {
			return
		}
		c.value.SampledTX++
		c.value.MaxTXBytes = max(c.value.MaxTXBytes, size)
		if long {
			c.value.SentLong++
		} else {
			c.value.SentShort++
		}
	} else {
		if c.value.SampledRX >= maxQUICPacketSamples {
			return
		}
		c.value.SampledRX++
		c.value.MaxRXBytes = max(c.value.MaxRXBytes, size)
		if long {
			c.value.ReceivedLong++
		} else {
			c.value.ReceivedShort++
		}
		if !expectedPeer {
			c.value.UnexpectedPeerPackets++
		}
	}
}

func (s *Session) NoteMSSClamp(inbound bool) {
	if s.quicStats == nil {
		return
	}
	s.quicStats.mu.Lock()
	defer s.quicStats.mu.Unlock()
	if inbound {
		s.quicStats.value.MSSIn++
	} else {
		s.quicStats.value.MSSOut++
	}
}

func (s *Session) NotePacketTooBig() {
	if s.quicStats == nil {
		return
	}
	s.quicStats.mu.Lock()
	defer s.quicStats.mu.Unlock()
	s.quicStats.value.PacketTooBig++
}

func (s *Session) QUICStatistics() (QUICStatistics, bool) {
	if s.quicStats == nil {
		return QUICStatistics{}, false
	}
	s.quicStats.mu.Lock()
	out := s.quicStats.value
	s.quicStats.mu.Unlock()
	out.ElapsedMs = time.Since(s.quicStats.started).Milliseconds()
	out.CloseKind = "active"
	if s.quicCause != nil {
		err := s.quicCause()
		var reset *quic.StatelessResetError
		var idle *quic.IdleTimeoutError
		var handshake *quic.HandshakeTimeoutError
		var application *quic.ApplicationError
		var transport *quic.TransportError
		switch {
		case err == nil:
		case errors.As(err, &reset):
			out.CloseKind = "stateless_reset"
		case errors.As(err, &idle):
			out.CloseKind = "idle_timeout"
		case errors.As(err, &handshake):
			out.CloseKind = "handshake_timeout"
		case errors.As(err, &application):
			out.CloseKind = "application_error"
		case errors.As(err, &transport):
			out.CloseKind = "transport_error"
		default:
			out.CloseKind = "closed"
		}
	}
	return out, true
}
