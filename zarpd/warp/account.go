// Package warp registers and connects native WARP MASQUE using pinned usque.
// The account setup client owns HTTP contexts and durable enrollment checkpoints;
// it does not use usque's contextless registration requests.
package warp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	usqueconfig "github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/models"
	"golang.org/x/sys/unix"
)

const (
	registerModel  = "PC"
	registerLocale = "en_US"
)

// Register creates a new WARP device, enrolls a MASQUE (P-256) key for it, and writes the
// resulting config to configPath. The caller must have obtained the user's consent to the
// Cloudflare WARP Terms of Service before calling it (acceptTos=true below assumes that).
func Register(configPath, deviceName string) error {
	return RegisterContext(context.Background(), configPath, deviceName)
}

func RegisterContext(ctx context.Context, configPath, deviceName string) error {
	service := Registration{Path: configPath, DeviceName: deviceName, Factory: func(_ context.Context, s *RegistrationStrategy) (http.RoundTripper, error) {
		return NewRegistrationTransport(s, nil)
	}}
	_, err := service.Do(ctx, AccountSetupRequest{Version: AccountSetupVersion, Operation: "register"})
	return err
}

func configFromAccount(upd *models.AccountData, token string, privKeyDER []byte) (*usqueconfig.Config, error) {
	if len(upd.Config.Peers) == 0 {
		return nil, errors.New("enroll key: response has no peers")
	}
	peer := upd.Config.Peers[0]
	v4, err := stripPort(peer.Endpoint.V4)
	if err != nil {
		return nil, fmt.Errorf("endpoint v4 %q: %w", peer.Endpoint.V4, err)
	}
	v6, _ := stripPort(peer.Endpoint.V6) // IPv6 endpoint is optional
	return &usqueconfig.Config{
		PrivateKey:     base64.StdEncoding.EncodeToString(privKeyDER),
		EndpointV4:     v4,
		EndpointV6:     v6,
		EndpointH2V4:   usqueconfig.DefaultEndpointH2V4,
		EndpointH2V6:   usqueconfig.DefaultEndpointH2V6,
		EndpointPubKey: peer.PublicKey,
		ID:             upd.ID,
		AccessToken:    token,
		IPv4:           upd.Config.Interface.Addresses.V4,
		IPv6:           upd.Config.Interface.Addresses.V6,
	}, nil
}

// stripPort turns "162.159.198.1:0" or "[2606:4700::1]:0" into a bare IP.
func stripPort(hostPort string) (string, error) {
	if hostPort == "" {
		return "", errors.New("empty")
	}
	host := hostPort
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if net.ParseIP(host) == nil {
		return "", errors.New("not an IP address")
	}
	return host, nil
}

func writeConfig(path string, cfg *usqueconfig.Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Account files are small JSON documents. Status/ping must never open a FIFO,
// device or unbounded file as an account. This limit also applies if a regular
// file grows after its initial size check. No account bytes appear in errors.
const maxAccountConfigBytes = 64 * 1024

// LoadConfig reads a bounded regular account file without following a final
// symlink. Nonblocking open precedes descriptor validation so a FIFO cannot
// stall the caller while it still holds the account-status mutex.
func LoadConfig(path string) (*usqueconfig.Config, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err // unix.Open returns errno without a secret-bearing path.
	}
	input := os.NewFile(uintptr(fd), "warp-account")
	defer input.Close()
	info, err := input.Stat()
	if err != nil {
		return nil, errors.New("account file metadata unavailable")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() <= 0 || info.Size() > maxAccountConfigBytes {
		return nil, errors.New("account file is not a bounded protected regular file")
	}
	data, err := io.ReadAll(io.LimitReader(input, maxAccountConfigBytes+1))
	if err != nil {
		return nil, errors.New("account file read failed")
	}
	if len(data) > maxAccountConfigBytes {
		return nil, errors.New("account file exceeds size limit")
	}
	var cfg usqueconfig.Config
	if json.Unmarshal(data, &cfg) != nil {
		return nil, errors.New("invalid account data")
	}
	if cfg.PrivateKey == "" || cfg.EndpointPubKey == "" {
		return nil, errors.New("account file missing keys")
	}
	return &cfg, nil
}

// HasAccount reports whether configPath holds a usable WARP registration.
func HasAccount(configPath string) bool {
	_, err := LoadConfig(configPath)
	return err == nil
}

// AccountEndpoint returns the MASQUE endpoint IPv4 address assigned at registration.
func AccountEndpoint(configPath string) (string, error) {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return "", err
	}
	return cfg.EndpointV4, nil
}
