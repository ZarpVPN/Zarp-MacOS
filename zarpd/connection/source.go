package connection

import (
	"encoding/json"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

type SourceKind string

const (
	WarpSource         SourceKind = "warp"
	ManualSource       SourceKind = "manual"
	SubscriptionSource SourceKind = "subscription"
	MaxSourceURLBytes             = 8192
	MaxSourceBytes                = 16384
)

// Source is pure metadata. Token-bearing URLs never trigger network access or
// WARP registration here and are not accepted by the production open handler.
type Source struct {
	Kind            SourceKind `json:"kind"`
	Label           string     `json:"label"`
	SubscriptionURL *string    `json:"subscriptionURL,omitempty"`
}

func (Source) String() string   { return "ConnectionSource(redacted)" }
func (Source) GoString() string { return "ConnectionSource(redacted)" }
func (s Source) Mode() Mode {
	if s.Kind == WarpSource {
		return Warp
	}
	return Server
}
func (s Source) ID() string {
	return "source-v1-" + fingerprint([]string{"connection-source-v1", string(s.Kind), pointerValue(s.SubscriptionURL)})
}
func (s Source) Validate() error {
	if s.Kind != WarpSource && s.Kind != ManualSource && s.Kind != SubscriptionSource {
		return Error{"source"}
	}
	if !text(s.Label, 128) {
		return Error{"label"}
	}
	if s.Kind == SubscriptionSource {
		if s.SubscriptionURL == nil || !validHTTPSURL(*s.SubscriptionURL) {
			return Error{"sourceURL"}
		}
	} else if s.SubscriptionURL != nil {
		return Error{"sourceURL"}
	}
	return nil
}

func validHTTPSURL(value string) bool {
	if len(value) == 0 || len(value) > MaxSourceURLBytes {
		return false
	}
	for _, c := range []byte(value) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~:/?@!$&'()*+,;=%[]", rune(c))) {
			return false
		}
	}
	decoded, err := url.PathUnescape(value)
	if err != nil || !text(decoded, MaxSourceURLBytes) {
		return false
	}
	u, err := url.Parse(value)
	// Never return net/url errors: they may include the entire secret-bearing URL.
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" || strings.ContainsAny(u.Host, "%") || strings.HasSuffix(u.Host, ":") ||
		strings.ContainsAny(u.EscapedPath(), "[]") || strings.ContainsAny(u.RawQuery, "[]") {
		return false
	}
	// Keep validation independent of Go's optional urlstrictcolons compatibility switch.
	if !strings.HasPrefix(u.Host, "[") && strings.Count(u.Host, ":") > 1 {
		return false
	}
	if port := u.Port(); port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return false
		}
	}
	name := u.Hostname()
	if strings.HasPrefix(u.Host, "[") {
		address, err := netip.ParseAddr(name)
		return err == nil && address.Is6() && address.Zone() == "" && !strings.Contains(name, ".")
	}
	return host(name)
}

func DecodeSource(data []byte) (Source, error) {
	if len(data) > MaxSourceBytes || !strictJSON(data) {
		return Source{}, Error{"source"}
	}
	var s Source
	if err := json.Unmarshal(data, &s); err != nil {
		return Source{}, err
	}
	return s, nil
}
func (s *Source) UnmarshalJSON(data []byte) error {
	o, err := decodeObject(data, "source", "kind", "label", "subscriptionURL")
	if err != nil {
		return err
	}
	if s.Kind, err = required[SourceKind](o, "kind", "source"); err != nil {
		return err
	}
	if s.Kind != WarpSource && s.Kind != ManualSource && s.Kind != SubscriptionSource {
		return Error{"source"}
	}
	if s.Label, err = optional(o, "label", "label", ""); err != nil {
		return err
	}
	if s.SubscriptionURL, err = optional[*string](o, "subscriptionURL", "sourceURL", nil); err != nil {
		return err
	}
	return s.Validate()
}
