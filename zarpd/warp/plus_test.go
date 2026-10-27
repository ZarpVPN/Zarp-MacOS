package warp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	usqueconfig "github.com/Diniboy1123/usque/config"
)

type accountTransport func(*http.Request) (*http.Response, error)

func (f accountTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func accountResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}
func accountFixture() *usqueconfig.Config {
	return &usqueconfig.Config{ID: "test-device-id", AccessToken: "private-account-token", PrivateKey: "private-device-key", EndpointPubKey: "private-peer-key"}
}

func TestAccountLicenseValidationAndPublicTypes(t *testing.T) {
	if !ValidLicense("aB123456-abcdefgh-87654321") {
		t.Fatal("valid reference format refused")
	}
	for _, value := range []string{"", "aB123456-abcdefgh-87654321\n", "aB123456_abcdefgh_87654321", "秘密123456-abcdefgh-87654321", "--license $(command)"} {
		if ValidLicense(value) {
			t.Fatal("invalid license accepted")
		}
	}
	for _, item := range []struct {
		input string
		plus  bool
		want  AccountType
	}{
		{"free", false, AccountFree}, {"limited", false, AccountPlus}, {"unlimited", false, AccountUnlimited},
		{"team", false, AccountZeroTrust}, {"private-secret", false, AccountUnknown}, {"", true, AccountPlus},
	} {
		if accountType(item.input, item.plus) != item.want {
			t.Fatal("account type mapping failed")
		}
	}
}

func TestApplyLicenseUsesOwnAccountAndDoesNotModifyCredentials(t *testing.T) {
	cfg := accountFixture()
	before := *cfg
	methods := []string{}
	a := &AccountAPI{transport: accountTransport(func(r *http.Request) (*http.Response, error) {
		methods = append(methods, r.Method)
		if r.URL.String() != "https://api.cloudflareclient.com/v0a4471/reg/test-device-id/account" || r.Header.Get("Authorization") != "Bearer private-account-token" {
			t.Fatal("wrong account endpoint or credential")
		}
		if r.Method == http.MethodPut {
			data, _ := io.ReadAll(r.Body)
			if string(data) != `{"license":"aB123456-abcdefgh-87654321"}` {
				t.Fatal("license request format differs")
			}
			return accountResponse(200, `{"license":"private-response-secret"}`), nil
		}
		return accountResponse(200, `{"account_type":"unlimited","license":"private-response-secret","id":"private-account-id"}`), nil
	})}
	status, err := a.Apply(context.Background(), cfg, "aB123456-abcdefgh-87654321")
	if err != nil || status.AccountType != AccountUnlimited || !status.LicenseApplied || !reflect.DeepEqual(*cfg, before) {
		t.Fatal("license did not preserve the account or confirm its type", err)
	}
	if !reflect.DeepEqual(methods, []string{"PUT", "GET"}) {
		t.Fatal("unexpected account requests")
	}
	public, _ := json.Marshal(status)
	if strings.Contains(string(public), "private-") || strings.Contains(string(public), "aB123456") {
		t.Fatal("public account status exposed secrets")
	}
}

func TestAcceptedKeyWithFailedConfirmationIsNotReportedAsConfirmed(t *testing.T) {
	a := &AccountAPI{transport: accountTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPut {
			return accountResponse(200, ""), nil
		}
		return nil, errors.New("private-license-transport-error")
	})}
	status, err := a.Apply(context.Background(), accountFixture(), "aB123456-abcdefgh-87654321")
	if err != nil || !status.LicenseApplied || status.AccountType != AccountUnknown {
		t.Fatal("acceptance conflated with confirmation")
	}
}

func TestAccountRejectsRedirectOversizeAndUntrustedCredentialsWithoutSecretErrors(t *testing.T) {
	for _, code := range []int{302, 401, 500, 200} {
		calls := 0
		a := &AccountAPI{transport: accountTransport(func(r *http.Request) (*http.Response, error) {
			calls++
			response := accountResponse(code, strings.Repeat("private-response-secret", maxAccountConfigBytes))
			response.Header.Set("Location", "https://other.example/private-secret")
			return response, nil
		})}
		_, err := a.Read(context.Background(), accountFixture())
		if err == nil || strings.Contains(err.Error(), "private-") || calls != 1 {
			t.Fatal("unsafe account response accepted or leaked", code)
		}
	}
	calls := 0
	a := &AccountAPI{transport: accountTransport(func(*http.Request) (*http.Response, error) { calls++; return nil, ErrAccountRequest })}
	cfg := accountFixture()
	cfg.ID = "../private-secret"
	if _, err := a.Read(context.Background(), cfg); !errors.Is(err, ErrAccountUnavailable) || calls != 0 {
		t.Fatal("untrusted account path reached HTTP")
	}
}

func TestAccountCancellationReachesTransport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{})
	a := &AccountAPI{transport: accountTransport(func(r *http.Request) (*http.Response, error) {
		close(entered)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}
	done := make(chan error, 1)
	go func() { _, err := a.Read(ctx, accountFixture()); done <- err }()
	<-entered
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("account request ignored cancellation")
	}
}
