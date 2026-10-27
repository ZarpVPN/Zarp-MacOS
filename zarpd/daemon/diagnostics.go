package daemon

import (
	"fmt"
	"strings"
	"time"

	"github.com/feg55/zarp-macos/zarpd/ipc"
)

const (
	closedReasonLifetime = 2 * time.Minute
	maxClosedReasons     = 128
)

type closedReason struct {
	failure ipc.ConnError
	at      time.Time
	seq     uint64
}

func diagnosticStrategyID(id string) string {
	if len(id) > 192 {
		return "custom"
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-_.@", c)) {
			return "custom"
		}
	}
	return id
}

func terminalFailure(e *entry, code, reason string) ipc.ConnError {
	// Bound a diagnostic retained after teardown. Transport errors are not config.
	if len(reason) > 1024 {
		reason = reason[:1024]
	}
	reason = strings.Map(func(c rune) rune {
		if c < 32 || c == 127 {
			return ' '
		}
		return c
	}, reason)
	return ipc.ConnError{Code: code, Message: fmt.Sprintf("connection #%s ended: %s", e.id, reason),
		Connection: &ipc.ConnectionFailure{Endpoint: e.info.Endpoint, Transport: e.params.Transport,
			Phase: "traffic", StrategyID: diagnosticStrategyID(e.params.StrategyID), ConnectionID: e.id}}
}

func (m *Manager) pruneClosedReasonsLocked() {
	now := m.cfg.Now()
	for id, record := range m.closedReasons {
		if now.Sub(record.at) >= closedReasonLifetime {
			delete(m.closedReasons, id)
		}
	}
}

func (m *Manager) rememberClosedReasonLocked(e *entry) {
	if e.terminalFailure == nil {
		return
	}
	m.pruneClosedReasonsLocked()
	if len(m.closedReasons) >= maxClosedReasons {
		var oldestID string
		var oldestSeq uint64
		for id, record := range m.closedReasons {
			if oldestID == "" || record.seq < oldestSeq {
				oldestID, oldestSeq = id, record.seq
			}
		}
		delete(m.closedReasons, oldestID)
	}
	m.closedReasons[e.id] = closedReason{failure: *e.terminalFailure, at: m.cfg.Now(), seq: e.seq}
}

func connectionEndReason(conn Conn) string {
	if err := conn.Err(); err != nil {
		return err.Error()
	}
	return "the connection ended"
}

func (m *Manager) measurementConnection(id string) (*entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneClosedReasonsLocked()
	if m.cleanupFailed {
		return nil, cleanupError()
	}
	e, ok := m.conns[id]
	if ok {
		if e.closing {
			failure := terminalFailure(e, ipc.CodeConnectionClosed, "connection is closing")
			if e.terminalFailure != nil {
				failure = *e.terminalFailure
			}
			return nil, &failure
		}
		select {
		case <-e.conn.Done():
			failure := terminalFailure(e, ipc.CodeConnectionLost, connectionEndReason(e.conn))
			return nil, &failure
		default:
		}
		return e, nil
	}
	if record, exists := m.closedReasons[id]; exists {
		failure := record.failure
		return nil, &failure
	}
	return nil, fmt.Errorf("no open connection #%s", id)
}

func (m *Manager) finishMeasurement(e *entry, result ipc.MeasureResult) (any, error) {
	if _, err := m.measurementConnection(e.id); err != nil {
		return nil, err
	}
	return result, nil
}
