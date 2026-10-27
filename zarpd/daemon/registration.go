package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"

	"github.com/feg55/zarp-macos/zarpd/connection"
	"github.com/feg55/zarp-macos/zarpd/ipc"
	"github.com/feg55/zarp-macos/zarpd/route"
	"github.com/feg55/zarp-macos/zarpd/warp"
)

type accountSetupStore interface {
	Setup(context.Context, warp.AccountSetupRequest, bool) (warp.AccountSetupResult, error)
	State() string
}

func (m *Manager) accountSetupVersion() int {
	if _, ok := m.cfg.Accounts.(accountSetupStore); ok {
		return warp.AccountSetupVersion
	}
	return 0
}
func (m *Manager) accountState() string {
	if store, ok := m.cfg.Accounts.(accountSetupStore); ok {
		return store.State()
	}
	return ""
}

// Admission shares the tunnel semaphore. Shutdown cancels and joins setup work;
// account calls never stop or replace an existing persistent connection.
func (m *Manager) beginAccountOperation(parent context.Context, timeout time.Duration, requireIdle bool) (context.Context, func(), bool, error) {
	select {
	case m.openSem <- struct{}{}:
	default:
		return nil, nil, false, &ipc.ConnError{Code: ipc.CodeBusy, Message: "another operation is in progress"}
	}
	m.mu.Lock()
	bad := m.stopping || m.cleanupFailed || m.opening > 0 || parent.Err() != nil || (requireIdle && len(m.conns) > 0)
	for _, e := range m.conns {
		if !e.params.Persistent || e.closing {
			bad = true
		}
	}
	if bad {
		m.mu.Unlock()
		<-m.openSem
		return nil, nil, false, &ipc.ConnError{Code: ipc.CodeBusy, Message: "another operation is in progress"}
	}
	allowProtected := len(m.conns) == 0
	ctx, cancel := context.WithTimeout(parent, timeout)
	m.openCancel = cancel
	m.accountBusy = true
	m.mu.Unlock()
	finish := func() {
		cancel()
		m.mu.Lock()
		m.openCancel = nil
		m.accountBusy = false
		m.mu.Unlock()
		<-m.openSem
	}
	return ctx, finish, allowProtected, nil
}

func (m *Manager) setupWarpAccount(ctx context.Context, raw json.RawMessage) (any, error) {
	var input warp.AccountSetupRequest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if connection.ValidateDocumentJSON(raw, 16384) != nil || decoder.Decode(&input) != nil || !input.Valid() {
		return nil, &ipc.ConnError{Code: ipc.CodeBadRequest, Message: "invalid WARP account setup parameters"}
	}
	store, ok := m.cfg.Accounts.(accountSetupStore)
	if !ok {
		return nil, &ipc.ConnError{Code: ipc.CodeUnsupported, Message: "protected account setup is unavailable"}
	}
	ctx, finish, allowProtected, err := m.beginAccountOperation(ctx, warp.AccountSetupTimeout, false)
	if err != nil {
		return nil, err
	}
	defer finish()
	result, err := store.Setup(ctx, input, allowProtected)
	if err != nil {
		return nil, accountSetupError(err)
	}
	return result, nil
}

func accountSetupError(err error) error {
	if errors.Is(err, context.Canceled) {
		return cancelled()
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &ipc.ConnError{Code: "account_timeout", Message: "WARP account setup timed out", TimedOut: true}
	}
	var setup *warp.SetupError
	if errors.As(err, &setup) {
		return &ipc.ConnError{Code: setup.Code, Message: setup.Error()}
	}
	return &ipc.ConnError{Code: "account_request", Message: "WARP account setup failed"}
}

// RegistrationTransport only reads route state and binds its own API socket.
// No system proxy, DNS, routes, interfaces or other processes are changed.
func RegistrationTransport(router *route.Router) func(context.Context, *warp.RegistrationStrategy) (http.RoundTripper, error) {
	return func(ctx context.Context, strategy *warp.RegistrationStrategy) (http.RoundTripper, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		if strategy != nil {
			if router == nil {
				return nil, &warp.SetupError{Code: "unsupported"}
			}
			dialer.ControlContext = func(ctx context.Context, network, address string, raw syscall.RawConn) error {
				if err := ctx.Err(); err != nil {
					return err
				}
				target, err := netip.ParseAddrPort(address)
				if err != nil {
					return &warp.SetupError{Code: ipc.CodeBadRequest}
				}
				physical, err := router.InspectPhysical(ctx, target.Addr().Is6())
				if err != nil {
					if ctx.Err() != nil {
						return ctx.Err()
					}
					return &warp.SetupError{Code: ipc.CodeForeignVPN}
				}
				if physical == nil || physical.IsTunnel() {
					return &warp.SetupError{Code: ipc.CodeForeignVPN}
				}
				return physical.Control(network, address, raw)
			}
		}
		return warp.NewRegistrationTransport(strategy, dialer)
	}
}
