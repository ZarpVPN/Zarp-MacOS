// Package connection validates the draft shared connection contract. It is pure
// data and is not registered with the production protocol 3 open handler.
package connection

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const SchemaVersion = 1
const MaxProfileBytes = 16384
const MaxRequestBytes = 65536

type Field string

const (
	Version         Field = "version"
	ModeField       Field = "mode"
	ProfileField    Field = "profile"
	Parameters      Field = "parameters"
	CredentialField Field = "credential"
)

type Error struct{ Field Field }

func (e Error) Error() string { return "invalid connection field: " + string(e.Field) }

type Mode string

const (
	Warp   Mode = "warp"
	Server Mode = "server"
)

func (m Mode) RequiresWarpAccount() bool { return m == Warp }
func (m Mode) ProbeKind() string {
	if m == Warp {
		return "warpTrace"
	}
	return "serverHTTPS"
}

type Credential struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

func (Credential) String() string   { return "ServerCredential(redacted)" }
func (Credential) GoString() string { return "ServerCredential(redacted)" }

type Profile struct {
	Label            string     `json:"label"`
	Host             string     `json:"host"`
	Port             int        `json:"port"`
	Protocol         string     `json:"serverProtocol"`
	Credential       Credential `json:"credential"`
	Transport        string     `json:"transport"`
	Security         string     `json:"security"`
	ServerName       *string    `json:"serverName,omitempty"`
	ALPN             []string   `json:"alpn"`
	Flow             string     `json:"flow"`
	Path             *string    `json:"path,omitempty"`
	HostHeader       *string    `json:"hostHeader,omitempty"`
	ServiceName      *string    `json:"serviceName,omitempty"`
	Fingerprint      *string    `json:"fingerprint,omitempty"`
	PublicKey        *string    `json:"publicKey,omitempty"`
	ShortID          *string    `json:"shortId,omitempty"`
	Obfs             *string    `json:"obfs,omitempty"`
	ObfsPassword     *string    `json:"obfsPassword,omitempty"`
	XHTTPMode        *string    `json:"xhttpMode,omitempty"`
	XHTTPExtra       *string    `json:"xhttpExtra,omitempty"`
	XHTTPPadding     *string    `json:"xhttpPadding,omitempty"`
	ECHConfig        *string    `json:"echConfig,omitempty"`
	CertificatePins  []string   `json:"certificatePins,omitempty"`
	CertificateNames []string   `json:"certificateNames,omitempty"`
	SpiderX          *string    `json:"spiderX,omitempty"`
	MLDSAVerify      *string    `json:"mldsaVerify,omitempty"`
}

func (Profile) String() string   { return "ServerProfile(redacted)" }
func (Profile) GoString() string { return "ServerProfile(redacted)" }
func (p Profile) OuterTransport() string {
	if p.Protocol == "hysteria2" || p.Transport == "xhttp" && len(p.ALPN) == 1 && p.ALPN[0] == "h3" {
		return "udp"
	}
	return "tcp"
}

func text(value string, max int) bool {
	return len(value) <= max && utf8.ValidString(value) && !strings.ContainsFunc(value, func(r rune) bool {
		return unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
	})
}
func host(value string) bool {
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Zone() == "" && !(strings.Contains(value, ":") && strings.Contains(value, "."))
	}
	if len(value) == 0 || len(value) > 253 || strings.ContainsAny(value, ":%") {
		return false
	}
	parts := strings.Split(value, ".")
	allDigits := len(parts) == 4
	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				allDigits = false
			}
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return !allDigits
}
func uuid(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	raw, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	return err == nil && len(raw) == 16
}
func (p Profile) Validate() error {
	if err := p.validateTransportOptions(); err != nil {
		return err
	}
	if !text(p.Label, 128) {
		return Error{"label"}
	}
	if !host(p.Host) {
		return Error{"host"}
	}
	if p.Port < 1 || p.Port > 65535 {
		return Error{"port"}
	}
	if !text(p.Credential.Value, 4096) || p.Credential.Value == "" {
		return Error{CredentialField}
	}
	switch p.Protocol {
	case "vless":
		if p.Credential.Kind != "uuid" || !uuid(p.Credential.Value) {
			return Error{CredentialField}
		}
	case "trojan", "hysteria2":
		if p.Credential.Kind != "password" {
			return Error{CredentialField}
		}
	default:
		return Error{"serverProtocol"}
	}
	if p.ServerName != nil && !host(*p.ServerName) {
		return Error{"serverName"}
	}
	if len(p.ALPN) > 8 {
		return Error{"alpn"}
	}
	for _, value := range p.ALPN {
		if value == "" || !text(value, 255) {
			return Error{"alpn"}
		}
	}
	if p.Transport != "tcp" && p.Transport != "ws" && p.Transport != "grpc" && p.Transport != "httpUpgrade" && p.Transport != "quic" && p.Transport != "xhttp" {
		return Error{"transport"}
	}
	if p.Security != "none" && p.Security != "tls" && p.Security != "reality" {
		return Error{"security"}
	}
	switch p.Protocol {
	case "hysteria2":
		if p.Transport != "quic" {
			return Error{"transport"}
		}
		if p.Security != "tls" {
			return Error{"security"}
		}
	case "trojan":
		if p.Transport == "quic" {
			return Error{"transport"}
		}
		if p.Security != "tls" {
			return Error{"security"}
		}
	case "vless":
		if p.Transport == "quic" {
			return Error{"transport"}
		}
	}
	if p.Flow != "none" && (p.Flow != "vision" || p.Protocol != "vless" || p.Transport != "tcp" || p.Security == "none") {
		return Error{"flow"}
	}
	if p.Security == "none" && (p.ServerName != nil || len(p.ALPN) != 0) {
		return Error{"security"}
	}
	if p.Security == "reality" {
		if p.Protocol != "vless" || !(p.Transport == "tcp" || p.Transport == "xhttp") {
			return Error{"security"}
		}
		if p.ServerName == nil {
			return Error{"serverName"}
		}
		if _, err := netip.ParseAddr(*p.ServerName); err == nil {
			return Error{"serverName"}
		}
		if p.Fingerprint == nil {
			return Error{"fingerprint"}
		}
		if p.PublicKey == nil {
			return Error{"publicKey"}
		}
		raw, err := base64.RawURLEncoding.DecodeString(*p.PublicKey)
		if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != *p.PublicKey {
			return Error{"publicKey"}
		}
		if p.ShortID != nil {
			raw, err := hex.DecodeString(*p.ShortID)
			if err != nil || len(raw) > 8 {
				return Error{"shortId"}
			}
		}
	} else {
		if p.PublicKey != nil {
			return Error{"publicKey"}
		}
		if p.ShortID != nil {
			return Error{"shortId"}
		}
	}
	if p.Fingerprint != nil && (!contains([]string{"chrome", "firefox", "edge", "safari", "ios", "android", "random", "randomized", "qq", "360",
		"chrome_psk", "chrome_psk_shuffle", "chrome_padding_psk_shuffle", "chrome_pq", "chrome_pq_psk"}, *p.Fingerprint) || p.Security == "none" || p.Protocol == "hysteria2") {
		return Error{"fingerprint"}
	}
	if p.Obfs != nil {
		if *p.Obfs != "salamander" || p.Protocol != "hysteria2" {
			return Error{"obfs"}
		}
		if p.ObfsPassword == nil || *p.ObfsPassword == "" || !text(*p.ObfsPassword, 4096) {
			return Error{"obfsPassword"}
		}
	} else if p.ObfsPassword != nil {
		return Error{"obfsPassword"}
	}
	if p.Path != nil && (!(p.Transport == "ws" || p.Transport == "httpUpgrade" || p.Transport == "xhttp") || !strings.HasPrefix(*p.Path, "/") || !text(*p.Path, 2048)) {
		return Error{"path"}
	}
	if p.HostHeader != nil && (!(p.Transport == "ws" || p.Transport == "httpUpgrade" || p.Transport == "xhttp") || !host(*p.HostHeader)) {
		return Error{"hostHeader"}
	}
	if p.ServiceName != nil && (p.Transport != "grpc" || *p.ServiceName == "" || !text(*p.ServiceName, 256)) {
		return Error{"serviceName"}
	}
	return nil
}
func pointerValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
func (p Profile) ID() string {
	fields := []string{p.Protocol, strings.ToLower(p.Host), strconv.Itoa(p.Port), p.Credential.Kind, p.Credential.Value,
		p.Transport, p.Security, pointerValue(p.ServerName), strconv.Itoa(len(p.ALPN))}
	fields = append(fields, p.ALPN...)
	fields = append(fields, p.Flow, pointerValue(p.Path), pointerValue(p.HostHeader), pointerValue(p.ServiceName))
	// Optional extension preserves every pre-existing schema 1 identity.
	if p.Fingerprint != nil || p.PublicKey != nil || p.ShortID != nil || p.Obfs != nil || p.ObfsPassword != nil {
		fields = append(fields, "server-options-v1", pointerValue(p.Fingerprint), pointerValue(p.PublicKey), pointerValue(p.ShortID), pointerValue(p.Obfs), pointerValue(p.ObfsPassword))
	}
	if p.hasTransportOptions() {
		fields = append(fields, p.transportOptionIdentity()...)
	}
	return "server-v1-" + fingerprint(fields)
}

func fingerprint(fields []string) string {
	var buffer strings.Builder
	for _, value := range fields {
		fmt.Fprintf(&buffer, "%d:%s", len(value), value)
	}
	digest := sha256.Sum256([]byte(buffer.String()))
	return hex.EncodeToString(digest[:])
}

func DecodeProfile(data []byte) (Profile, error) {
	if len(data) > MaxProfileBytes || !strictJSON(data) {
		return Profile{}, Error{ProfileField}
	}
	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return Profile{}, err
	}
	return p, nil
}
func (p *Profile) UnmarshalJSON(data []byte) error {
	o, err := decodeObject(data, ProfileField, "label", "host", "port", "serverProtocol", "credential", "transport", "security", "serverName", "alpn", "flow", "path", "hostHeader", "serviceName", "fingerprint", "publicKey", "shortId", "obfs", "obfsPassword", "xhttpMode", "xhttpExtra", "xhttpPadding", "echConfig", "certificatePins", "certificateNames", "spiderX", "mldsaVerify")
	if err != nil {
		return err
	}
	if p.Label, err = optional(o, "label", "label", ""); err != nil {
		return err
	}
	if p.Host, err = required[string](o, "host", "host"); err != nil {
		return err
	}
	if p.Port, err = required[int](o, "port", "port"); err != nil {
		return err
	}
	if p.Protocol, err = required[string](o, "serverProtocol", "serverProtocol"); err != nil {
		return err
	}
	if p.Protocol != "vless" && p.Protocol != "trojan" && p.Protocol != "hysteria2" {
		return Error{"serverProtocol"}
	}
	if p.Credential, err = required[Credential](o, "credential", CredentialField); err != nil {
		return err
	}
	if p.Transport, err = required[string](o, "transport", "transport"); err != nil {
		return err
	}
	if p.Security, err = required[string](o, "security", "security"); err != nil {
		return err
	}
	if p.ServerName, err = optional[*string](o, "serverName", "serverName", nil); err != nil {
		return err
	}
	if p.ALPN, err = optional(o, "alpn", "alpn", []string{}); err != nil {
		return err
	}
	if p.Flow, err = optional(o, "flow", "flow", "none"); err != nil {
		return err
	}
	if p.Path, err = optional[*string](o, "path", "path", nil); err != nil {
		return err
	}
	if p.HostHeader, err = optional[*string](o, "hostHeader", "hostHeader", nil); err != nil {
		return err
	}
	if p.ServiceName, err = optional[*string](o, "serviceName", "serviceName", nil); err != nil {
		return err
	}
	if p.Fingerprint, err = optional[*string](o, "fingerprint", "fingerprint", nil); err != nil {
		return err
	}
	if p.Fingerprint != nil && !contains([]string{"chrome", "firefox", "edge", "safari", "ios", "android", "random", "randomized", "qq", "360",
		"chrome_psk", "chrome_psk_shuffle", "chrome_padding_psk_shuffle", "chrome_pq", "chrome_pq_psk"}, *p.Fingerprint) {
		return Error{"fingerprint"}
	}
	if p.PublicKey, err = optional[*string](o, "publicKey", "publicKey", nil); err != nil {
		return err
	}
	if p.ShortID, err = optional[*string](o, "shortId", "shortId", nil); err != nil {
		return err
	}
	if p.Obfs, err = optional[*string](o, "obfs", "obfs", nil); err != nil {
		return err
	}
	if p.Obfs != nil && *p.Obfs != "salamander" {
		return Error{"obfs"}
	}
	if p.ObfsPassword, err = optional[*string](o, "obfsPassword", "obfsPassword", nil); err != nil {
		return err
	}
	if p.XHTTPMode, err = optional[*string](o, "xhttpMode", "modeOptions", nil); err != nil {
		return err
	}
	if p.XHTTPExtra, err = optional[*string](o, "xhttpExtra", "extra", nil); err != nil {
		return err
	}
	if p.XHTTPPadding, err = optional[*string](o, "xhttpPadding", "padding", nil); err != nil {
		return err
	}
	if p.ECHConfig, err = optional[*string](o, "echConfig", "ech", nil); err != nil {
		return err
	}
	if p.CertificatePins, err = optional[[]string](o, "certificatePins", "certificatePin", nil); err != nil {
		return err
	}
	if p.CertificateNames, err = optional[[]string](o, "certificateNames", "certificateName", nil); err != nil {
		return err
	}
	if p.SpiderX, err = optional[*string](o, "spiderX", "parameters", nil); err != nil {
		return err
	}
	if p.MLDSAVerify, err = optional[*string](o, "mldsaVerify", "publicKey", nil); err != nil {
		return err
	}

	return p.Validate()
}
func (c *Credential) UnmarshalJSON(data []byte) error {
	o, err := decodeObject(data, CredentialField, "kind", "value")
	if err != nil {
		return Error{CredentialField}
	}
	if c.Kind, err = required[string](o, "kind", CredentialField); err != nil {
		return err
	}
	if c.Value, err = required[string](o, "value", CredentialField); err != nil {
		return err
	}
	if c.Kind != "uuid" && c.Kind != "password" {
		return Error{CredentialField}
	}
	return nil
}

type Options struct {
	DialTimeoutMs  int  `json:"dialTimeoutMs"`
	ProbeTimeoutMs int  `json:"probeTimeoutMs"`
	Persistent     bool `json:"persistent"`
	RouteAll       bool `json:"routeAll"`
	OverrideDNS    bool `json:"overrideDNS"`
	AllowPlain     bool `json:"allowPlain"`
}

func DefaultOptions() Options { return Options{DialTimeoutMs: 15000, ProbeTimeoutMs: 15000} }
func (o Options) Validate(mode Mode) error {
	if o.DialTimeoutMs < 1 || o.DialTimeoutMs > 120000 || o.ProbeTimeoutMs < 1 || o.ProbeTimeoutMs > 120000 {
		return Error{"timeout"}
	}
	if o.RouteAll && !o.Persistent || o.OverrideDNS && !o.RouteAll {
		return Error{"routing"}
	}
	if mode != Server && o.AllowPlain {
		return Error{"plain"}
	}
	return nil
}
func (o *Options) UnmarshalJSON(data []byte) error {
	fields, err := decodeObject(data, Parameters, "dialTimeoutMs", "probeTimeoutMs", "persistent", "routeAll", "overrideDNS", "allowPlain")
	if err != nil {
		return Error{Parameters}
	}
	*o = DefaultOptions()
	if o.DialTimeoutMs, err = optional(fields, "dialTimeoutMs", Parameters, o.DialTimeoutMs); err != nil {
		return err
	}
	if o.ProbeTimeoutMs, err = optional(fields, "probeTimeoutMs", Parameters, o.ProbeTimeoutMs); err != nil {
		return err
	}
	if o.Persistent, err = optional(fields, "persistent", Parameters, false); err != nil {
		return err
	}
	if o.RouteAll, err = optional(fields, "routeAll", Parameters, false); err != nil {
		return err
	}
	if o.OverrideDNS, err = optional(fields, "overrideDNS", Parameters, false); err != nil {
		return err
	}
	if o.AllowPlain, err = optional(fields, "allowPlain", Parameters, false); err != nil {
		return err
	}
	return nil
}

type Capabilities struct {
	Version         int      `json:"schemaVersion"`
	Modes           []Mode   `json:"modes"`
	Protocols       []string `json:"serverProtocols"`
	OuterTransports []string `json:"outerTransports"`
}

func CurrentWarpOnly() Capabilities {
	return Capabilities{Version: SchemaVersion, Modes: []Mode{Warp}, Protocols: []string{}, OuterTransports: []string{"tcp", "udp"}}
}

func CurrentServerRuntime() Capabilities {
	return Capabilities{Version: SchemaVersion, Modes: []Mode{Warp, Server}, Protocols: []string{"vless", "trojan", "hysteria2"}, OuterTransports: []string{"tcp", "udp"}}
}
func contains[T comparable](values []T, value T) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
func (c Capabilities) Require(mode Mode, profile *Profile) error {
	if c.Version != SchemaVersion {
		return Error{Version}
	}
	if !contains(c.Modes, mode) {
		return Error{"capabilities"}
	}
	if mode == Server {
		if profile == nil {
			return Error{ProfileField}
		}
		if err := profile.Validate(); err != nil {
			return err
		}
		if !contains(c.Protocols, profile.Protocol) || !contains(c.OuterTransports, profile.OuterTransport()) {
			return Error{"capabilities"}
		}
	} else if profile != nil {
		return Error{ProfileField}
	}
	return nil
}

type Request struct {
	Version    int      `json:"version"`
	Mode       Mode     `json:"mode"`
	ProbeKind  string   `json:"probeKind"`
	StrategyID *string  `json:"strategyId,omitempty"`
	Profile    *Profile `json:"profile,omitempty"`
	Options    Options  `json:"options"`
}

func (Request) String() string   { return "ConnectionRequest(redacted)" }
func (Request) GoString() string { return "ConnectionRequest(redacted)" }
func (r Request) Validate(capabilities Capabilities) error {
	if r.Version != SchemaVersion {
		return Error{Version}
	}
	if r.Mode != Warp && r.Mode != Server {
		return Error{ModeField}
	}
	if r.ProbeKind != r.Mode.ProbeKind() {
		return Error{"probeKind"}
	}
	if err := r.Options.Validate(r.Mode); err != nil {
		return err
	}
	if (r.Mode == Server) != (r.Profile != nil) {
		return Error{ProfileField}
	}
	if r.StrategyID != nil {
		if *r.StrategyID == "" || !text(*r.StrategyID, 128) {
			return Error{"strategyId"}
		}
	} else if r.Mode == Warp || !r.Options.AllowPlain {
		return Error{"plain"}
	}
	return capabilities.Require(r.Mode, r.Profile)
}
func DecodeRequest(data []byte, capabilities Capabilities) (Request, error) {
	if len(data) > MaxRequestBytes || !strictJSON(data) {
		return Request{}, Error{Parameters}
	}
	var r Request
	if err := json.Unmarshal(data, &r); err != nil {
		return Request{}, err
	}
	if err := r.Validate(capabilities); err != nil {
		return Request{}, err
	}
	return r, nil
}
func (r *Request) UnmarshalJSON(data []byte) error {
	o, err := decodeObject(data, Parameters, "version", "mode", "probeKind", "strategyId", "profile", "options")
	if err != nil {
		return err
	}
	if r.Version, err = required[int](o, "version", Version); err != nil {
		return err
	}
	if r.Mode, err = required[Mode](o, "mode", ModeField); err != nil {
		return err
	}
	if r.Mode != Warp && r.Mode != Server {
		return Error{ModeField}
	}
	if r.ProbeKind, err = required[string](o, "probeKind", "probeKind"); err != nil {
		return err
	}
	if r.ProbeKind != "warpTrace" && r.ProbeKind != "serverHTTPS" {
		return Error{"probeKind"}
	}
	if r.StrategyID, err = optional[*string](o, "strategyId", "strategyId", nil); err != nil {
		return err
	}
	if r.Profile, err = optional[*Profile](o, "profile", ProfileField, nil); err != nil {
		return err
	}
	if r.Options, err = required[Options](o, "options", Parameters); err != nil {
		return err
	}
	return nil
}
