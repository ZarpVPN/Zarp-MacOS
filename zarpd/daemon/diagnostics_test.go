package daemon

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/feg55/zarp-macos/zarpd/ipc"
)

type gatedDiagnosticMeasurer struct {
	entered, release chan struct{}
	once             sync.Once
}

func (m *gatedDiagnosticMeasurer) Measure(_ context.Context, _ string, _ int) ipc.MeasureResult {
	m.once.Do(func() { close(m.entered) })
	<-m.release
	return ipc.MeasureResult{Kind: "ok", PingMs: 10, Warp: "on"}
}

func TestAResetDuringMeasurementCannotReturnSuccess(t *testing.T) {
	h := newHarness(t, time.Minute)
	measurer := &gatedDiagnosticMeasurer{entered: make(chan struct{}), release: make(chan struct{})}
	h.m.cfg.Measurer = measurer
	opened := h.open(t, scanTest)
	done := make(chan error, 1)
	go func() {
		_, err := h.call(t, context.Background(), "measure", ipc.MeasureParams{ConnectionID: opened.ConnectionID, Samples: 1})
		done <- err
	}()
	signalWithin(t, measurer.entered)
	h.opener.conn(0).die(errors.New("received a stateless reset"))
	waitFor(t, "reset cleanup", func() bool { return !h.status(t).NetworkBusy })
	close(measurer.release)
	if err := errorWithin(t, done); codeOf(err) != ipc.CodeConnectionLost || !strings.Contains(err.Error(), "stateless reset") {
		t.Fatal("measurement returned success after its tunnel ended", err)
	}
}

func TestScanMeasurementRetainsStatelessResetAfterJoinedCleanup(t *testing.T) {
	h := newHarness(t, time.Minute)
	opened := h.open(t, scanTest)
	h.opener.conn(0).die(errors.New("connect-ip read: received a stateless reset"))
	waitFor(t, "joined scan cleanup", func() bool { return !h.status(t).NetworkBusy })
	_, err := h.call(t, context.Background(), "measure", ipc.MeasureParams{ConnectionID: opened.ConnectionID, Samples: 1})
	var ce *ipc.ConnError
	if !errors.As(err, &ce) || ce.Code != ipc.CodeConnectionLost || !strings.Contains(ce.Message, "stateless reset") {
		t.Fatalf("lost the original scan error: %v", err)
	}
	if ce.Connection == nil || ce.Connection.ConnectionID != opened.ConnectionID || ce.Connection.Endpoint != opened.Endpoint || ce.Connection.Phase != "traffic" {
		t.Fatalf("lost connection context: %+v", ce.Connection)
	}
	if len(h.measurer.hosts) != 0 || h.status(t).LastLoss != nil {
		t.Fatal("measured another connection or published a scan as persistent loss")
	}
	newer := h.open(t, scanTest)
	_, err = h.call(t, context.Background(), "measure", ipc.MeasureParams{ConnectionID: opened.ConnectionID, Samples: 1})
	if codeOf(err) != ipc.CodeConnectionLost || len(h.measurer.hosts) != 0 {
		t.Fatal("old handle measured the new tunnel")
	}
	_, err = h.call(t, context.Background(), "measure", ipc.MeasureParams{ConnectionID: newer.ConnectionID, Samples: 1})
	if err != nil || len(h.measurer.hosts) != 1 {
		t.Fatal("old loss poisoned the new tunnel", err)
	}
}

func TestMeasurementReportsLossWhileOwnedCleanupIsStillRunning(t *testing.T) {
	h := newHarness(t, time.Minute)
	opened := h.open(t, scanTest)
	gate := gateConnection(t, h, opened.ConnectionID)
	h.opener.conn(0).die(errors.New("received a stateless reset"))
	signalWithin(t, gate.started)
	_, err := h.call(t, context.Background(), "measure", ipc.MeasureParams{ConnectionID: opened.ConnectionID, Samples: 1})
	if codeOf(err) != ipc.CodeConnectionLost || !strings.Contains(err.Error(), "stateless reset") {
		t.Fatal(err)
	}
	if !h.status(t).NetworkBusy {
		t.Fatal("unjoined cleanup advertised idle")
	}
	gate.unblock()
	waitFor(t, "cleanup", func() bool { return !h.status(t).NetworkBusy })
}

func TestClosedReasonsExpireAndRemainBoundedWithoutExtendingOnRead(t *testing.T) {
	h := newHarness(t, time.Minute)
	now := time.Unix(1000, 0)
	h.m.cfg.Now = func() time.Time { return now }
	for i := 0; i <= maxClosedReasons; i++ {
		opened := h.open(t, scanTest)
		if _, err := h.call(t, context.Background(), "close", ipc.CloseParams{ConnectionID: opened.ConnectionID}); err != nil {
			t.Fatal(err)
		}
	}
	if len(h.m.closedReasons) != maxClosedReasons {
		t.Fatal("unbounded retained handles", len(h.m.closedReasons))
	}
	if _, exists := h.m.closedReasons["1"]; exists {
		t.Fatal("oldest handle was not evicted")
	}
	last := "129"
	_, err := h.call(t, context.Background(), "measure", ipc.MeasureParams{ConnectionID: last, Samples: 1})
	if codeOf(err) != ipc.CodeConnectionClosed {
		t.Fatal("explicit close became spontaneous loss", err)
	}
	now = now.Add(closedReasonLifetime)
	_, err = h.call(t, context.Background(), "measure", ipc.MeasureParams{ConnectionID: last, Samples: 1})
	if err == nil || codeOf(err) != "" || len(h.m.closedReasons) != 0 {
		t.Fatal("expired reason was refreshed by reading", err)
	}
}

func TestCleanupFailureStillOverridesRetainedTransportReason(t *testing.T) {
	h := newHarness(t, time.Minute)
	opened := h.open(t, scanTest)
	gate := gateConnection(t, h, opened.ConnectionID)
	gate.failure = errors.New("private cleanup failure")
	h.opener.conn(0).die(errors.New("received a stateless reset"))
	signalWithin(t, gate.started)
	gate.unblock()
	waitFor(t, "sticky cleanup failure", func() bool { h.m.mu.Lock(); defer h.m.mu.Unlock(); return h.m.cleanupFailed })
	_, err := h.call(t, context.Background(), "measure", ipc.MeasureParams{ConnectionID: opened.ConnectionID, Samples: 1})
	if codeOf(err) != ipc.CodeInternal || strings.Contains(err.Error(), "private") {
		t.Fatal("cleanup refusal lost", err)
	}
}
