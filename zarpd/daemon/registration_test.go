package daemon

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/feg55/zarp-macos/zarpd/ipc"
	"github.com/feg55/zarp-macos/zarpd/warp"
)

type setupAccounts struct {
	*fakeAccounts
	entered, joined chan struct{}
	allowProtected  bool
	calls           int
}

func (a *setupAccounts) State() string { return "ready" }
func (a *setupAccounts) Setup(ctx context.Context, input warp.AccountSetupRequest, allow bool) (warp.AccountSetupResult, error) {
	a.calls++
	a.allowProtected = allow
	if a.entered != nil {
		close(a.entered)
		<-ctx.Done()
		close(a.joined)
		return warp.AccountSetupResult{}, ctx.Err()
	}
	return warp.AccountSetupResult{AccountStatus: warp.AccountStatus{AccountType: warp.AccountPlus, LicenseApplied: input.Operation == "license"}, AccountRegistered: true}, nil
}

func TestAccountSetupCapabilityAdmissionAndPersistentConnection(t *testing.T) {
	h := newHarness(t, time.Minute)
	a := &setupAccounts{fakeAccounts: h.accounts}
	h.m.cfg.Accounts = a
	answer, err := h.m.Handle(context.Background(), "ping", nil)
	if err != nil {
		t.Fatal(err)
	}
	ping := answer.(ipc.PingResult)
	if ping.AccountSetupVersion != 1 || ping.WarpAccountState != "ready" {
		t.Fatal("capability missing")
	}
	opened := h.open(t, persistent)
	result, err := h.m.Handle(context.Background(), "setupWarpAccount", json.RawMessage(`{"version":1,"operation":"license","license":"aB123456-abcdefgh-87654321","strategies":[]}`))
	if err != nil || !result.(warp.AccountSetupResult).LicenseApplied {
		t.Fatal(err)
	}
	if a.allowProtected || h.m.Status().ConnectionID != opened.ConnectionID || h.opener.conn(0).closeCount() != 0 {
		t.Fatal("setup disturbed existing tunnel or allowed physical bypass")
	}
	for _, raw := range []string{
		`{"version":1,"operation":"register","origin":"https://private-secret"}`,
		`{"version":1,"operation":"license","license":"private-secret"}`,
		`{"version":1,"operation":"register","version":1}`,
		`{"version":1,"operation":"register","strategies":[{"id":"tls","mode":"fake","positions":["1"]}]}`,
	} {
		_, err := h.m.Handle(context.Background(), "setupWarpAccount", json.RawMessage(raw))
		if codeOf(err) != ipc.CodeBadRequest || strings.Contains(err.Error(), "private-secret") {
			t.Fatal("unsafe parameters accepted or exposed", err)
		}
	}
	if a.calls != 1 {
		t.Fatal("invalid IPC reached account store")
	}
}

func TestAccountSetupShutdownCancelsAndJoinsWorker(t *testing.T) {
	h := newHarness(t, time.Minute)
	a := &setupAccounts{fakeAccounts: h.accounts, entered: make(chan struct{}), joined: make(chan struct{})}
	h.m.cfg.Accounts = a
	done := make(chan error, 1)
	go func() {
		_, err := h.m.Handle(context.Background(), "setupWarpAccount", json.RawMessage(`{"version":1,"operation":"register","strategies":[]}`))
		done <- err
	}()
	signalWithin(t, a.entered)
	if !h.m.Status().NetworkBusy {
		t.Fatal("setup advertised idle")
	}
	_, err := h.m.Handle(context.Background(), "setupWarpAccount", json.RawMessage(`{"version":1,"operation":"register"}`))
	if codeOf(err) != ipc.CodeBusy {
		t.Fatal("concurrent setup admitted", err)
	}
	if err := h.m.CloseAll(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-a.joined:
	default:
		t.Fatal("shutdown returned before request joined")
	}
	if codeOf(errorWithin(t, done)) != ipc.CodeCancelled {
		t.Fatal("shutdown did not cancel setup")
	}
}
