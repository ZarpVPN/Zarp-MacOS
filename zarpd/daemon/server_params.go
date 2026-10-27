package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"

	"github.com/feg55/zarp-macos/zarpd/connection"
	"github.com/feg55/zarp-macos/zarpd/ipc"
)

func (m *Manager) capabilities() connection.Capabilities {
	if opener, ok := m.cfg.Opener.(interface{ ServerAvailable() bool }); ok && opener.ServerAvailable() {
		return connection.CurrentServerRuntime()
	}
	return connection.CurrentWarpOnly()
}

type serverOpenParams struct {
	Profile       connection.Profile        `json:"profile"`
	SourceID      string                    `json:"sourceId"`
	StrategyID    string                    `json:"strategyId"`
	FakeSteps     []ipc.FakeStep            `json:"fakeSteps,omitempty"`
	TCPDesync     *ipc.TCPDesync            `json:"tcpDesync,omitempty"`
	TimeoutMs     int                       `json:"timeoutMs"`
	Persistent    bool                      `json:"persistent"`
	RouteAll      bool                      `json:"routeAll"`
	OverrideDNS   bool                      `json:"overrideDNS"`
	AllowPlain    bool                      `json:"allowPlain"`
	RoutingPolicy *connection.RoutingPolicy `json:"routingPolicy,omitempty"`
}

func (m *Manager) serverRoutingVersion() int {
	if opener, ok := m.cfg.Opener.(interface{ ApplicationRoutingAvailable() bool }); ok && opener.ApplicationRoutingAvailable() {
		return 1
	}
	return 0
}

func (m *Manager) openServer(ctx context.Context, raw json.RawMessage) (any, error) {
	bad := func() (any, error) {
		return nil, &ipc.ConnError{Code: ipc.CodeBadRequest, Message: "invalid server connection parameters"}
	}
	if connection.ValidateDocumentJSON(raw, connection.MaxRequestBytes) != nil {
		return bad()
	}
	var request serverOpenParams
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return bad()
	}
	if err := request.Profile.Validate(); err != nil {
		return bad()
	}
	if err := m.capabilities().Require(connection.Server, &request.Profile); err != nil {
		return nil, &ipc.ConnError{Code: ipc.CodeUnsupported, Message: "server backends are not installed in this build"}
	}
	if len(request.SourceID) != 74 || !strings.HasPrefix(request.SourceID, "source-v1-") {
		return bad()
	}
	for _, b := range []byte(request.SourceID[10:]) {
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
			return bad()
		}
	}
	if !strings.HasSuffix(request.StrategyID, "@"+request.Profile.ID()) {
		return bad()
	}
	if !request.AllowPlain && len(request.FakeSteps) == 0 && request.TCPDesync == nil {
		return bad()
	}
	if request.RoutingPolicy != nil {
		if !request.Persistent || !request.RouteAll || request.RoutingPolicy.Validate() != nil {
			return bad()
		}
		if m.serverRoutingVersion() != 1 {
			return nil, &ipc.ConnError{Code: ipc.CodeUnsupported, Message: "application routing is unavailable in this daemon"}
		}
	}
	transport := "masqueH2"
	if request.Profile.OuterTransport() == "udp" {
		transport = "masqueH3"
	}
	p := ipc.OpenParams{Mode: "server", Profile: &request.Profile, SourceID: request.SourceID, AllowPlain: request.AllowPlain,
		Transport: transport, StrategyID: request.StrategyID, FakeSteps: request.FakeSteps, TCPDesync: request.TCPDesync,
		TimeoutMs: request.TimeoutMs, Persistent: request.Persistent, RouteAll: request.RouteAll, OverrideDNS: request.OverrideDNS, RoutingPolicy: request.RoutingPolicy}
	if p.Validate() != nil {
		return bad()
	}
	return m.openParams(ctx, p)
}
