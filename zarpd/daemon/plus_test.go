package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/feg55/zarp-macos/zarpd/ipc"
	"github.com/feg55/zarp-macos/zarpd/warp"
)

type plusAccounts struct {
	*fakeAccounts
	entered chan struct{}
	block   bool
	err     error
}

func (a *plusAccounts) ReadWarpAccount(ctx context.Context) (warp.AccountStatus, error) {
	if a.entered != nil {
		close(a.entered)
	}
	if a.block {
		<-ctx.Done()
		return warp.AccountStatus{}, ctx.Err()
	}
	return warp.AccountStatus{AccountType: warp.AccountPlus}, a.err
}
func (a *plusAccounts) ApplyWarpLicense(ctx context.Context, key string) (warp.AccountStatus, error) {
	status, err := a.ReadWarpAccount(ctx)
	status.LicenseApplied = err == nil
	return status, err
}

func TestWarpPlusPreservesPersistentTunnelAndRejectsSecretParameters(t *testing.T) {
	h := newHarness(t, time.Minute)
	h.m.cfg.Accounts = &plusAccounts{fakeAccounts: h.accounts}
	_, err := h.call(t, context.Background(), "open", ipc.OpenParams{Transport: "masqueH3", Persistent: true, StrategyID: "warp-q-google6", FakeSteps: []ipc.FakeStep{{Blob: "quic_google", Repeats: 6}}})
	if err != nil {
		t.Fatal(err)
	}
	before := h.m.Status()
	result, err := h.m.Handle(context.Background(), "warpLicense", json.RawMessage(`{"license":"aB123456-abcdefgh-87654321"}`))
	if err != nil || result.(warp.AccountStatus).AccountType != warp.AccountPlus {
		t.Fatal("license operation failed", err)
	}
	after := h.m.Status()
	if !after.Connected || after.ConnectionID != before.ConnectionID || after.StrategyID != before.StrategyID || h.opener.conn(0).closeCount() != 0 {
		t.Fatal("license operation replaced a tunnel or strategy")
	}
	for _, raw := range []string{`{"license":123}`, `{"private-secret":"x"}`, `{"license":"private-secret"}`, `{"license":"aB123456-abcdefgh-87654321","license":"private-secret"}`} {
		_, err := h.m.Handle(context.Background(), "warpLicense", json.RawMessage(raw))
		if err == nil || strings.Contains(err.Error(), "private-") {
			t.Fatal("unsafe license error or accepted invalid request")
		}
	}
	h.m.cfg.Accounts.(*plusAccounts).err = errors.New("private-license-value")
	_, err = h.m.Handle(context.Background(), "warpAccount", nil)
	if err == nil || strings.Contains(err.Error(), "private-") {
		t.Fatal("raw account error exposed")
	}
}

func TestWarpAccountBusyStatusAndShutdownJoinOnlyItsOwnOperation(t *testing.T) {
	h := newHarness(t, time.Minute)
	a := &plusAccounts{fakeAccounts: h.accounts, entered: make(chan struct{}), block: true}
	h.m.cfg.Accounts = a
	done := make(chan error, 1)
	go func() { _, err := h.m.Handle(context.Background(), "warpAccount", nil); done <- err }()
	<-a.entered
	if !h.m.Status().NetworkBusy {
		t.Fatal("account work was advertised as idle")
	}
	if _, err := h.m.Handle(context.Background(), "warpAccount", nil); err == nil {
		t.Fatal("concurrent account work was admitted")
	}
	if err := h.m.CloseAll(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil {
		t.Fatal("shutdown failed to cancel account operation")
	}
}
