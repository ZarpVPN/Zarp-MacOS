package warp

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	usqueconfig "github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/models"
	"golang.org/x/sys/unix"
)

const AccountSetupVersion = 1
const AccountSetupTimeout = 180 * time.Second
const accountOrigin = "https://api.cloudflareclient.com/v0a4471"

// SetupError carries only fixed diagnostics. API bodies and credentials stay private.
type SetupError struct {
	Code      string
	Retryable bool
}

func (e *SetupError) Error() string { return "WARP account setup: " + e.Code }

type RegistrationStrategy struct {
	ID        string   `json:"id"`
	Mode      string   `json:"mode"`
	Positions []string `json:"positions"`
}

func (s RegistrationStrategy) Validate() bool {
	if len(s.ID) == 0 || len(s.ID) > 256 || strings.IndexFunc(s.ID, func(r rune) bool { return r < 32 || r == 127 }) >= 0 || (s.Mode != "split" && s.Mode != "disorder") || len(s.Positions) == 0 || len(s.Positions) > 16 {
		return false
	}
	for _, p := range s.Positions {
		switch p {
		case "host", "endhost", "sld", "midsld":
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil || n == 0 || n < -8192 || n > 8192 {
			return false
		}
	}
	return true
}

type AccountSetupRequest struct {
	Version    int                    `json:"version"`
	Operation  string                 `json:"operation"`
	Strategies []RegistrationStrategy `json:"strategies"`
	License    string                 `json:"license,omitempty"`
}

func (r AccountSetupRequest) Valid() bool {
	if r.Version != AccountSetupVersion || len(r.Strategies) > 32 || (r.Operation != "register" && r.Operation != "license" && r.Operation != "status") || (r.Operation == "license" && !ValidLicense(r.License)) || (r.Operation != "license" && r.License != "") {
		return false
	}
	seen := map[string]bool{}
	for _, s := range r.Strategies {
		if !s.Validate() || seen[s.ID] {
			return false
		}
		seen[s.ID] = true
	}
	return true
}

type AccountSetupResult struct {
	AccountStatus
	AccountRegistered bool `json:"accountRegistered"`
	APIProtected      bool `json:"apiProtected"`
}

// Registration owns one serialized setup. Factory is trusted daemon construction
// data, never an origin, proxy or socket policy supplied over IPC.
type Registration struct {
	Path, DeviceName string
	Factory          func(context.Context, *RegistrationStrategy) (http.RoundTripper, error)
	Notify           func(phase string, attempt, total int)
}

type pendingRegistration struct {
	Version      int    `json:"version"`
	Phase        string `json:"phase"`
	ID           string `json:"id"`
	Token        string `json:"token"`
	PrivateKey   string `json:"privateKey"`
	PublicKey    string `json:"publicKey"`
	WireGuardKey string `json:"wireGuardKey"`
	Serial       string `json:"serial"`
	Tos          string `json:"tos"`
}

func validIdentity(id, token string) bool {
	if len(id) == 0 || len(id) > 128 || len(token) == 0 || len(token) > 4096 {
		return false
	}
	for _, c := range []byte(id) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	for _, c := range []byte(token) {
		if c <= 32 || c >= 127 {
			return false
		}
	}
	return true
}

func readPending(path string) (*pendingRegistration, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, &SetupError{Code: "account_storage"}
	}
	f := os.NewFile(uintptr(fd), "pending-account")
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() <= 0 || info.Size() > maxAccountConfigBytes {
		return nil, &SetupError{Code: "account_storage"}
	}
	data, err := io.ReadAll(io.LimitReader(f, maxAccountConfigBytes+1))
	if err != nil || len(data) > maxAccountConfigBytes {
		return nil, &SetupError{Code: "account_storage"}
	}
	var p pendingRegistration
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&p) != nil || decoder.Decode(new(any)) != io.EOF || p.Version != 1 || (p.Phase != "prepared" && p.Phase != "creating" && p.Phase != "created") {
		return nil, &SetupError{Code: "account_storage"}
	}
	key, err := base64.StdEncoding.DecodeString(p.PrivateKey)
	if err != nil {
		return nil, &SetupError{Code: "account_storage"}
	}
	ec, err := x509.ParseECPrivateKey(key)
	if err != nil {
		return nil, &SetupError{Code: "account_storage"}
	}
	pub, err := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	if err != nil || base64.StdEncoding.EncodeToString(pub) != p.PublicKey {
		return nil, &SetupError{Code: "account_storage"}
	}
	wg, err := base64.StdEncoding.DecodeString(p.WireGuardKey)
	if err != nil || len(wg) != 32 || len(p.Serial) != 16 || len(p.Tos) > 64 || (p.Phase == "created" && !validIdentity(p.ID, p.Token)) || (p.Phase != "created" && (p.ID != "" || p.Token != "")) {
		return nil, &SetupError{Code: "account_storage"}
	}
	if _, err := hex.DecodeString(p.Serial); err != nil {
		return nil, &SetupError{Code: "account_storage"}
	}
	if _, err := time.Parse(time.RFC3339Nano, p.Tos); err != nil {
		return nil, &SetupError{Code: "account_storage"}
	}
	return &p, nil
}

// AccountState distinguishes absent data from unusable existing data. Neither
// damaged storage nor an uncertain POST grants permission to create an account.
func AccountState(path string) string {
	if _, err := LoadConfig(path); err == nil {
		return "ready"
	} else if !errors.Is(err, os.ErrNotExist) {
		return "unavailable"
	}
	p, err := readPending(path + ".registration-pending")
	if err != nil {
		return "unavailable"
	}
	if p == nil {
		return "missing"
	}
	if p.Phase == "creating" {
		return "uncertain"
	}
	return "pending"
}

func savePrivate(path string, value any, exclusive bool) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return &SetupError{Code: "account_storage"}
	}
	data, err := json.Marshal(value)
	if err != nil || len(data) > maxAccountConfigBytes {
		return &SetupError{Code: "account_storage"}
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".account-*")
	if err != nil {
		return &SetupError{Code: "account_storage"}
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return &SetupError{Code: "account_storage"}
	}
	if exclusive {
		err = os.Link(f.Name(), path)
	} else {
		err = os.Rename(f.Name(), path)
	}
	if err != nil {
		return &SetupError{Code: "account_storage"}
	}
	dir, err := os.Open(filepath.Dir(path))
	if err == nil {
		err = dir.Sync()
		dir.Close()
	}
	if err != nil {
		return &SetupError{Code: "account_storage"}
	}
	return nil
}

func newPending() (*pendingRegistration, error) {
	_, private, public, err := generateECKeyPair()
	if err != nil {
		return nil, &SetupError{Code: "account_storage"}
	}
	wg, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, &SetupError{Code: "account_storage"}
	}
	serial := make([]byte, 8)
	if _, err := rand.Read(serial); err != nil {
		return nil, &SetupError{Code: "account_storage"}
	}
	return &pendingRegistration{Version: 1, Phase: "prepared", PrivateKey: base64.StdEncoding.EncodeToString(private), PublicKey: base64.StdEncoding.EncodeToString(public), WireGuardKey: base64.StdEncoding.EncodeToString(wg.PublicKey().Bytes()), Serial: hex.EncodeToString(serial), Tos: time.Now().UTC().Format("2006-01-02T15:04:05.000-07:00")}, nil
}

func (r *Registration) Do(parent context.Context, input AccountSetupRequest) (AccountSetupResult, error) {
	result := AccountSetupResult{AccountStatus: AccountStatus{AccountType: AccountUnknown}}
	if !input.Valid() {
		return result, &SetupError{Code: "bad_request"}
	}
	ctx, cancel := context.WithTimeout(parent, AccountSetupTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return result, err
	}
	state := AccountState(r.Path)
	if state == "unavailable" || state == "uncertain" {
		return result, &SetupError{Code: "account_" + state}
	}
	var cfg *usqueconfig.Config
	var pending *pendingRegistration
	if state == "ready" {
		cfg, _ = LoadConfig(r.Path)
	} else {
		if input.Operation == "status" {
			return result, &SetupError{Code: "no_account"}
		}
		var err error
		pending, err = readPending(r.Path + ".registration-pending")
		if err != nil {
			return result, err
		}
		if pending == nil {
			pending, err = newPending()
			if err != nil {
				return result, err
			}
			if err = savePrivate(r.Path+".registration-pending", pending, true); err != nil {
				return result, err
			}
		}
	}
	if cfg != nil && input.Operation == "register" {
		result.AccountRegistered = true
		return result, nil
	}
	licenseAccepted, licenseUncertain := false, false
	choices := make([]*RegistrationStrategy, 1, len(input.Strategies)+1)
	for i := range input.Strategies {
		choices = append(choices, &input.Strategies[i])
	}
	var last error
	for attempt, strategy := range choices {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if r.Notify != nil {
			r.Notify("api", attempt, len(choices)-1)
		}
		var transport http.RoundTripper
		var transportErr error
		if r.Factory != nil {
			transport, transportErr = r.Factory(ctx, strategy)
		} else if strategy == nil {
			transport, transportErr = NewRegistrationTransport(nil, nil)
		} else {
			transportErr = &SetupError{Code: "unsupported"}
		}
		if transportErr != nil {
			return result, transportErr
		}
		client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		operation := func() error {
			if cfg == nil {
				if pending.Phase == "prepared" {
					pending.Phase = "creating"
					if err := savePrivate(r.Path+".registration-pending", pending, false); err != nil {
						return err
					}
					body, _ := json.Marshal(models.Registration{Key: pending.WireGuardKey, Tos: pending.Tos, Model: registerModel, Serial: pending.Serial, KeyType: "curve25519", TunType: "wireguard", Locale: registerLocale})
					data, sent, err := setupRequest(ctx, client, http.MethodPost, "/reg", "", body)
					if err != nil {
						var failure *SetupError
						// Rejected HTTP requests did not create a usable account. A lost
						// response after a POST remains uncertain and cannot be replayed.
						if !sent || (errors.As(err, &failure) && (failure.Code == "account_rate_limited" || failure.Code == "account_rejected")) {
							pending.Phase = "prepared"
							if saveErr := savePrivate(r.Path+".registration-pending", pending, false); saveErr != nil {
								return saveErr
							}
						} else {
							return &SetupError{Code: "account_uncertain"}
						}
						return err
					}
					var account models.AccountData
					if json.Unmarshal(data, &account) != nil || !validIdentity(account.ID, account.Token) {
						return &SetupError{Code: "account_uncertain"}
					}
					pending.ID, pending.Token, pending.Phase = account.ID, account.Token, "created"
					if err := savePrivate(r.Path+".registration-pending", pending, false); err != nil {
						return err
					}
				}
				if pending.Phase != "created" {
					return &SetupError{Code: "account_uncertain"}
				}
				body, _ := json.Marshal(models.DeviceUpdate{Key: pending.PublicKey, KeyType: "secp256r1", TunType: "masque", Name: r.DeviceName})
				data, _, err := setupRequest(ctx, client, http.MethodPatch, "/reg/"+pending.ID, pending.Token, body)
				if err != nil {
					return err
				}
				var account models.AccountData
				if json.Unmarshal(data, &account) != nil || account.ID != pending.ID {
					return &SetupError{Code: "account_response"}
				}
				private, _ := base64.StdEncoding.DecodeString(pending.PrivateKey)
				cfg, err = configFromAccount(&account, pending.Token, private)
				if err != nil || cfg.PrivateKey == "" || cfg.EndpointPubKey == "" {
					cfg = nil
					return &SetupError{Code: "account_response"}
				}
				if _, err := TLSConfigFromAccount(cfg); err != nil || net.ParseIP(cfg.IPv4) == nil {
					cfg = nil
					return &SetupError{Code: "account_response"}
				}
				if err := ctx.Err(); err != nil {
					return err
				}
				if err := savePrivate(r.Path, cfg, true); err != nil {
					return err
				}
				if err := os.Remove(r.Path + ".registration-pending"); err != nil {
					return &SetupError{Code: "account_storage"}
				}
			}
			result.AccountRegistered = true
			result.APIProtected = strategy != nil
			if input.Operation == "register" {
				return nil
			}
			if !validIdentity(cfg.ID, cfg.AccessToken) {
				return &SetupError{Code: "account_unavailable"}
			}
			path := "/reg/" + cfg.ID + "/account"
			if input.Operation == "license" && !licenseAccepted && !licenseUncertain {
				body, _ := json.Marshal(struct {
					License string `json:"license"`
				}{input.License})
				_, sent, err := setupRequest(ctx, client, http.MethodPut, path, cfg.AccessToken, body)
				if err != nil {
					var failure *SetupError
					if sent && errors.As(err, &failure) && failure.Retryable {
						licenseUncertain = true
					}
					return err
				}
				licenseAccepted = true
			}
			data, _, err := setupRequest(ctx, client, http.MethodGet, path, cfg.AccessToken, nil)
			if err != nil {
				return err
			}
			var account struct {
				AccountType string `json:"account_type"`
				WarpPlus    bool   `json:"warp_plus"`
			}
			if json.Unmarshal(data, &account) != nil {
				return &SetupError{Code: "account_response"}
			}
			result.AccountStatus = AccountStatus{AccountType: accountType(account.AccountType, account.WarpPlus), LicenseApplied: licenseAccepted}
			if licenseUncertain && result.AccountType != AccountPlus && result.AccountType != AccountUnlimited {
				return &SetupError{Code: "license_uncertain"}
			}
			return nil
		}
		last = operation()
		client.CloseIdleConnections()
		if last == nil {
			return result, nil
		}
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		var failure *SetupError
		if !errors.As(last, &failure) || !failure.Retryable {
			return result, last
		}
	}
	if licenseAccepted {
		result.AccountStatus = AccountStatus{AccountType: AccountUnknown, LicenseApplied: true}
		return result, nil
	}
	if licenseUncertain {
		return result, &SetupError{Code: "license_uncertain"}
	}
	return result, last
}

func setupRequest(ctx context.Context, client *http.Client, method, path, token string, body []byte) ([]byte, bool, error) {
	var sent atomic.Bool
	// Connection acquisition precedes HTTP writes. WroteHeaders alone can race
	// cancellation, so treat an acquired TLS connection as possible transmission.
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn:      func(httptrace.GotConnInfo) { sent.Store(true) },
		WroteHeaders: func() { sent.Store(true) },
	})
	req, err := http.NewRequestWithContext(ctx, method, accountOrigin+path, bytes.NewReader(body))
	if err != nil {
		return nil, false, &SetupError{Code: "bad_request"}
	}
	req.Header.Set("User-Agent", "WARP for Android")
	req.Header.Set("CF-Client-Version", "a-6.35-4471")
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, sent.Load(), ctx.Err()
		}
		var fixed *SetupError
		if errors.As(err, &fixed) {
			return nil, sent.Load(), fixed
		}
		var cert *tls.CertificateVerificationError
		if errors.As(err, &cert) {
			return nil, sent.Load(), &SetupError{Code: "account_certificate"}
		}
		return nil, sent.Load(), &SetupError{Code: "account_network", Retryable: true}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		code, retry := "account_rejected", false
		if response.StatusCode == 429 {
			code = "account_rate_limited"
		} else if response.StatusCode >= 500 || response.StatusCode == 408 {
			code, retry = "account_network", true
		}
		return nil, true, &SetupError{Code: code, Retryable: retry}
	}
	if method == http.MethodPut {
		return nil, true, nil
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxAccountConfigBytes+1))
	if err != nil {
		return nil, true, &SetupError{Code: "account_network", Retryable: true}
	}
	if len(data) > maxAccountConfigBytes {
		return nil, true, &SetupError{Code: "account_response"}
	}
	return data, true, nil
}
