package daemon

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/feg55/zarp-macos/zarpd/warp"
)

// FileAccounts is the real Accounts: the WARP registration lives in one root-owned JSON file
// (warp.LoadConfig/Register). Registration happens only when the app asks for it — after the user
// has accepted Cloudflare's WARP terms there — never at daemon startup, where it used to run
// unconditionally (with the terms auto-accepted, and with a failure — no network at boot — killing
// the process and launchd relaunching it into the same failure every few seconds).
type FileAccounts struct {
	Path       string
	DeviceName string
	// Timeout bounds and cancels all registration HTTP work.
	Timeout time.Duration
	// RegisterFn performs the registration (default warp.Register); tests substitute it.
	RegisterFn     func(context.Context, string, string) error
	AccountAPI     *warp.AccountAPI
	SetupTransport func(context.Context, *warp.RegistrationStrategy) (http.RoundTripper, error)
	SetupNotify    func(string, int, int)

	mu      sync.Mutex
	setupMu sync.Mutex
	has     bool
}

// Has reports whether a usable account is on disk. A positive answer is cached — an account does
// not un-register itself — so the frequent status/ping calls don't re-read the file.
func (a *FileAccounts) Has() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.has && warp.HasAccount(a.Path) {
		a.has = true
	}
	return a.has
}

// Register creates the account.
func (a *FileAccounts) Register(ctx context.Context) error {
	timeout := a.Timeout
	if timeout <= 0 {
		timeout = warp.AccountSetupTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if a.RegisterFn != nil {
		return a.RegisterFn(ctx, a.Path, a.DeviceName)
	}
	_, err := a.Setup(ctx, warp.AccountSetupRequest{Version: warp.AccountSetupVersion, Operation: "register"}, false)
	return err
}

func (a *FileAccounts) State() string { return warp.AccountState(a.Path) }

func (a *FileAccounts) Setup(ctx context.Context, input warp.AccountSetupRequest, allowProtected bool) (warp.AccountSetupResult, error) {
	a.setupMu.Lock()
	defer a.setupMu.Unlock()
	if err := ctx.Err(); err != nil {
		return warp.AccountSetupResult{}, err
	}
	service := warp.Registration{Path: a.Path, DeviceName: a.DeviceName, Notify: a.SetupNotify, Factory: func(ctx context.Context, s *warp.RegistrationStrategy) (http.RoundTripper, error) {
		if s != nil && !allowProtected {
			return nil, &warp.SetupError{Code: "foreign_vpn"}
		}
		if a.SetupTransport != nil {
			return a.SetupTransport(ctx, s)
		}
		if s != nil {
			return nil, &warp.SetupError{Code: "unsupported"}
		}
		return warp.NewRegistrationTransport(nil, nil)
	}}
	return service.Do(ctx, input)
}
