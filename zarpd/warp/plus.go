package warp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	usqueconfig "github.com/Diniboy1123/usque/config"
)

type AccountType string

const (
	AccountUnknown   AccountType = "unknown"
	AccountFree      AccountType = "free"
	AccountPlus      AccountType = "plus"
	AccountUnlimited AccountType = "unlimited"
	AccountZeroTrust AccountType = "zeroTrust"
)

// AccountStatus never contains an account ID, token, key or raw API response.
type AccountStatus struct {
	AccountType    AccountType `json:"accountType"`
	LicenseApplied bool        `json:"licenseApplied"`
}

var (
	ErrLicenseInvalid     = errors.New("invalid WARP+ license format")
	ErrAccountUnavailable = errors.New("WARP account credentials unavailable")
	ErrAccountRequest     = errors.New("Cloudflare account request failed")
	ErrLicenseRejected    = errors.New("Cloudflare did not accept the WARP+ license")
)

// Same format as the Windows 1.6 prerelease and the pinned usque account command.
func ValidLicense(key string) bool {
	if len(key) != 26 || key[8] != '-' || key[17] != '-' {
		return false
	}
	for i, b := range []byte(key) {
		if i == 8 || i == 17 {
			continue
		}
		if !(b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9') {
			return false
		}
	}
	return true
}

// AccountAPI implements the account endpoints used by pinned usque. Unlike its
// CLI helpers, these requests honor cancellation, bounds and a private client.
// A license is sent once to Cloudflare and is never written to the config.
type AccountAPI struct{ transport http.RoundTripper }

func NewAccountAPI() *AccountAPI { return &AccountAPI{} }

func accountType(value string, plus bool) AccountType {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "free":
		if plus {
			return AccountPlus
		}
		return AccountFree
	case "limited", "plus", "warp+":
		return AccountPlus
	case "unlimited", "warp+ unlimited":
		return AccountUnlimited
	case "team", "zero trust", "zerotrust":
		return AccountZeroTrust
	default:
		if plus {
			return AccountPlus
		}
		return AccountUnknown
	}
}

func (a *AccountAPI) Read(ctx context.Context, cfg *usqueconfig.Config) (AccountStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	return a.read(ctx, cfg)
}

func (a *AccountAPI) read(ctx context.Context, cfg *usqueconfig.Config) (AccountStatus, error) {
	data, err := a.request(ctx, cfg, http.MethodGet, nil)
	if err != nil {
		return AccountStatus{}, err
	}
	var response struct {
		AccountType string `json:"account_type"`
		WarpPlus    bool   `json:"warp_plus"`
	}
	if json.Unmarshal(data, &response) != nil {
		return AccountStatus{}, ErrAccountRequest
	}
	return AccountStatus{AccountType: accountType(response.AccountType, response.WarpPlus)}, nil
}

func (a *AccountAPI) Apply(ctx context.Context, cfg *usqueconfig.Config, key string) (AccountStatus, error) {
	if !ValidLicense(key) {
		return AccountStatus{}, ErrLicenseInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	body, _ := json.Marshal(struct {
		License string `json:"license"`
	}{key})
	if _, err := a.request(ctx, cfg, http.MethodPut, body); err != nil {
		return AccountStatus{}, err
	}
	status, err := a.read(ctx, cfg)
	if err != nil {
		// Acceptance and confirmation differ. Do not advise applying the same key
		// again merely because the follow-up GET failed or cancellation arrived.
		status = AccountStatus{AccountType: AccountUnknown}
	}
	status.LicenseApplied = true
	return status, nil
}

func (a *AccountAPI) request(ctx context.Context, cfg *usqueconfig.Config, method string, body []byte) ([]byte, error) {
	if cfg == nil || cfg.ID == "" || len(cfg.ID) > 128 || cfg.AccessToken == "" || len(cfg.AccessToken) > 4096 {
		return nil, ErrAccountUnavailable
	}
	for _, b := range []byte(cfg.ID) {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-') {
			return nil, ErrAccountUnavailable
		}
	}
	for _, b := range []byte(cfg.AccessToken) {
		if b <= 32 || b >= 127 {
			return nil, ErrAccountUnavailable
		}
	}
	// Endpoint and client headers match usque's pinned internal constants. Never
	// take the service URL from IPC, settings, a redirect or a subscription.
	url := "https://api.cloudflareclient.com/v0a4471/reg/" + cfg.ID + "/account"
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, ErrAccountRequest
	}
	req.Header.Set("Authorization", "Bearer "+cfg.AccessToken)
	req.Header.Set("User-Agent", "WARP for Android")
	req.Header.Set("CF-Client-Version", "a-6.35-4471")
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	client := &http.Client{Transport: a.transport, Timeout: 25 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrAccountRequest
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		if method == http.MethodPut {
			return nil, ErrLicenseRejected
		}
		return nil, ErrAccountRequest
	}
	if method == http.MethodPut {
		return nil, nil
	} // Do not read or persist its secret-bearing body.
	data, err := io.ReadAll(io.LimitReader(response.Body, maxAccountConfigBytes+1))
	if err != nil || len(data) > maxAccountConfigBytes {
		return nil, ErrAccountRequest
	}
	return data, nil
}
