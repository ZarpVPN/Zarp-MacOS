package daemon

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/feg55/zarp-macos/zarpd/connection"
	"github.com/feg55/zarp-macos/zarpd/ipc"
)

type availableServerOpener struct{ *fakeOpener }

func (availableServerOpener) ServerAvailable() bool { return true }

type routingServerOpener struct{ availableServerOpener }

func (routingServerOpener) ApplicationRoutingAvailable() bool { return true }

func TestApplicationRoutingCapabilityAndTypedPolicyReachTheOpener(t *testing.T) {
	for _, supported := range []bool{false, true} {
		h := newHarness(t, time.Minute)
		h.m.cfg.Opener = availableServerOpener{h.opener}
		if supported {
			h.m.cfg.Opener = routingServerOpener{availableServerOpener{h.opener}}
		}
		policy := connection.DefaultRoutingPolicy()
		policy.ApplicationMode = "include"
		policy.ApplicationPaths = []string{"/Applications/Browser.app"}
		request := serverRequestFixture()
		request.RouteAll = true
		request.RoutingPolicy = &policy
		_, err := h.call(t, context.Background(), "openServer", request)
		if !supported {
			if codeOf(err) != ipc.CodeUnsupported || h.opener.seen.Load() != 0 {
				t.Fatal("old daemon accepted application policy")
			}
			continue
		}
		if err != nil || len(h.opener.params) != 1 || h.opener.params[0].RoutingPolicy == nil || h.opener.params[0].RoutingPolicy.ApplicationPaths[0] != policy.ApplicationPaths[0] {
			t.Fatal("typed application policy was lost", err)
		}
	}
}

func serverRequestFixture() serverOpenParams {
	profile := connection.Profile{Host: "server.example", Port: 443, Protocol: "trojan", Credential: connection.Credential{Kind: "password", Value: "private-fixture-password"}, Transport: "tcp", Security: "tls", Flow: "none"}
	return serverOpenParams{Profile: profile, SourceID: "source-v1-" + strings.Repeat("a", 64), StrategyID: "split@" + profile.ID(), TCPDesync: &ipc.TCPDesync{Mode: "split", Positions: []string{"1", "host"}}, TimeoutMs: 15000, Persistent: true}
}

func TestServerIPCUsesTypedIdentityAndNeverNeedsWarpEnrollment(t *testing.T) {
	h := newHarness(t, time.Minute)
	h.m.cfg.Opener = availableServerOpener{h.opener}
	h.accounts.has = false
	request := serverRequestFixture()
	if _, err := h.call(t, context.Background(), "openServer", request); err != nil {
		t.Fatal(err)
	}
	status := h.status(t)
	if status.ActiveMode != "server" || status.ServerID != request.Profile.ID() || status.SourceID != request.SourceID {
		t.Fatal("server identity was not preserved")
	}
	if h.accounts.regCalls != 0 {
		t.Fatal("server mode registered a WARP account")
	}
	if h.opener.params[0].Mode != "server" || h.opener.params[0].Profile == nil || h.opener.params[0].Transport != "masqueH2" {
		t.Fatal("server request lost its internal mode")
	}
}

func TestServerIPCRejectsIdentityMismatchPlainAndLegacyFieldSmuggling(t *testing.T) {
	h := newHarness(t, time.Minute)
	h.m.cfg.Opener = availableServerOpener{h.opener}
	request := serverRequestFixture()
	data, _ := json.Marshal(request)
	for _, raw := range []string{
		strings.Replace(string(data), request.StrategyID, "split@server-v1-"+strings.Repeat("b", 64), 1),
		strings.Replace(string(data), `"sourceId":"`+request.SourceID+`"`, `"sourceId":"private-fixture-password"`, 1),
		strings.Replace(string(data), `"tcpDesync":{"mode":"split","positions":["1","host"]},`, "", 1),
		strings.TrimSuffix(string(data), "}") + `,"command":"private-fixture-password"}`,
	} {
		_, err := h.m.Handle(context.Background(), "openServer", json.RawMessage(raw))
		if codeOf(err) != ipc.CodeBadRequest {
			t.Fatal("invalid server request accepted:", err)
		}
		if strings.Contains(err.Error(), "private-fixture-password") {
			t.Fatal("secret leaked in validation error")
		}
	}
	_, err := h.m.Handle(context.Background(), "open", json.RawMessage(`{"transport":"masqueH2","mode":"server","profile":{},"strategyId":"split"}`))
	if codeOf(err) != ipc.CodeBadRequest || h.opener.seen.Load() != 0 {
		t.Fatal("legacy WARP request smuggled server fields")
	}
}

func TestServerMeasurementAcceptsOffWarpButRejectsUnrelatedResponse(t *testing.T) {
	_, m := traceServer(t, warpHandler("off"))
	if result := m.MeasureServer(context.Background(), "1.1.1.1", 1); result.Kind != "ok" || result.Warp != "off" {
		t.Fatal("server mode required WARP status")
	}
}
