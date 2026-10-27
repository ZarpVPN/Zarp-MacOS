package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/feg55/zarp-macos/zarpd/connection"
	"github.com/feg55/zarp-macos/zarpd/ipc"
	"github.com/feg55/zarp-macos/zarpd/warp"
)

type warpAccounts interface {
	ReadWarpAccount(context.Context) (warp.AccountStatus, error)
	ApplyWarpLicense(context.Context, string) (warp.AccountStatus, error)
}

func (a *FileAccounts) ReadWarpAccount(ctx context.Context) (warp.AccountStatus, error) {
	cfg, err := warp.LoadConfig(a.Path)
	if err != nil {
		return warp.AccountStatus{}, warp.ErrAccountUnavailable
	}
	return a.accountAPI().Read(ctx, cfg)
}

func (a *FileAccounts) ApplyWarpLicense(ctx context.Context, key string) (warp.AccountStatus, error) {
	cfg, err := warp.LoadConfig(a.Path)
	if err != nil {
		return warp.AccountStatus{}, warp.ErrAccountUnavailable
	}
	return a.accountAPI().Apply(ctx, cfg, key)
}

func (a *FileAccounts) accountAPI() *warp.AccountAPI {
	if a.AccountAPI != nil {
		return a.AccountAPI
	}
	return warp.NewAccountAPI()
}

func (m *Manager) warpAccount(ctx context.Context, raw json.RawMessage, apply bool) (any, error) {
	var p struct {
		License string `json:"license"`
	}
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	// Generic decoder diagnostics can echo a supplied key. Keep this method strict
	// and use only static messages, including for malformed/non-string parameters.
	var fields map[string]json.RawMessage
	if connection.ValidateDocumentJSON(raw, 4096) != nil || json.Unmarshal(raw, &fields) != nil || fields == nil || len(fields) > 1 ||
		(!apply && len(fields) != 0) || (apply && (fields["license"] == nil || json.Unmarshal(raw, &p) != nil || !warp.ValidLicense(p.License))) {
		return nil, &ipc.ConnError{Code: ipc.CodeBadRequest, Message: "invalid WARP account parameters"}
	}
	accounts, ok := m.cfg.Accounts.(warpAccounts)
	if !ok {
		return nil, &ipc.ConnError{Code: "unsupported", Message: "WARP+ is unavailable in this daemon"}
	}
	select {
	case m.openSem <- struct{}{}:
	default:
		return nil, &ipc.ConnError{Code: ipc.CodeBusy, Message: "another connection or account operation is in progress"}
	}
	defer func() { <-m.openSem }()
	m.mu.Lock()
	if m.stopping || m.cleanupFailed || m.opening > 0 || ctx.Err() != nil {
		m.mu.Unlock()
		return nil, &ipc.ConnError{Code: ipc.CodeBusy, Message: "another connection or account operation is in progress"}
	}
	for _, e := range m.conns {
		if !e.params.Persistent || e.closing {
			m.mu.Unlock()
			return nil, &ipc.ConnError{Code: ipc.CodeBusy, Message: "a test connection is in progress"}
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	m.openCancel = cancel
	m.accountBusy = true
	m.mu.Unlock()
	defer func() {
		cancel()
		m.mu.Lock()
		m.openCancel = nil
		m.accountBusy = false
		m.mu.Unlock()
	}()
	if !m.cfg.Accounts.Has() {
		return nil, &ipc.ConnError{Code: ipc.CodeNoAccount, Message: "register a WARP account after accepting the terms"}
	}
	var result warp.AccountStatus
	var err error
	if apply {
		result, err = accounts.ApplyWarpLicense(ctx, p.License)
	} else {
		result, err = accounts.ReadWarpAccount(ctx)
	}
	if err != nil {
		code := "account_request"
		if errors.Is(err, context.Canceled) {
			return nil, cancelled()
		}
		if errors.Is(err, context.DeadlineExceeded) {
			code = "account_timeout"
		}
		if errors.Is(err, warp.ErrAccountUnavailable) {
			code = ipc.CodeNoAccount
		}
		if errors.Is(err, warp.ErrLicenseRejected) {
			code = "license_rejected"
		}
		return nil, &ipc.ConnError{Code: code, Message: "WARP account operation failed"}
	}
	return result, nil
}
