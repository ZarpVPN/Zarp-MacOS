package ipc

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

func TestConnectionFailureContextCrossesPrivateIPC(t *testing.T) {
	contextInfo := &ConnectionFailure{Endpoint: "162.159.198.2:443", Transport: "masqueH2", Phase: "tls", StrategyID: "warp-t-split"}
	path, stop := startServer(t, func(_ context.Context, _ string, _ json.RawMessage) (any, error) {
		return nil, fmt.Errorf("wrapped: %w", &ConnError{Code: CodePeerKeyMismatch, Message: "wrong peer key", Connection: contextInfo})
	}, Options{})
	defer stop()
	c := dial(t, path)
	c.send(t, 1, "open", nil)
	response := c.recv(t)
	if response.Error == nil || response.Error.Code != CodePeerKeyMismatch || response.Error.Connection == nil || *response.Error.Connection != *contextInfo {
		t.Fatalf("lost additive error context: %+v", response.Error)
	}
}
