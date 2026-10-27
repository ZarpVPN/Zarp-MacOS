package connection

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"path"
	"strings"
	"unicode"
)

// RoutingPolicy contains data only. Application bundles match their own helpers.
type RoutingPolicy struct {
	Version          int      `json:"version"`
	ApplicationMode  string   `json:"applicationMode"`
	ApplicationPaths []string `json:"applicationPaths"`
	IPv6             bool     `json:"ipv6"`
	DNSServer        string   `json:"dnsServer"`
}

func DefaultRoutingPolicy() RoutingPolicy {
	return RoutingPolicy{Version: 1, ApplicationMode: "all", ApplicationPaths: []string{}, IPv6: true, DNSServer: "1.1.1.1"}
}

func (p RoutingPolicy) Validate() error {
	bad := Error{"routing"}
	if p.Version != 1 || !contains([]string{"all", "include", "exclude"}, p.ApplicationMode) || len(p.ApplicationPaths) > 128 || p.ApplicationMode == "include" && len(p.ApplicationPaths) == 0 {
		return bad
	}
	seen := map[string]bool{}
	for _, value := range p.ApplicationPaths {
		if !strings.HasPrefix(value, "/") || value == "/" || len(value) > 1024 || path.Clean(value) != value || seen[value] || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return bad
		}
		seen[value] = true
	}
	dns, err := netip.ParseAddr(p.DNSServer)
	if err != nil || dns.Zone() != "" || dns.IsUnspecified() || dns.IsMulticast() || dns.IsLoopback() || dns.IsLinkLocalUnicast() || dns.Is4In6() || !p.IPv6 && dns.Is6() || dns.Is4() && dns.As4()[0] >= 224 {
		return bad
	}
	encoded, err := json.Marshal(p)
	if err != nil || len(encoded) > 32768 {
		return bad
	}
	return nil
}

func (p *RoutingPolicy) UnmarshalJSON(data []byte) error {
	fields, err := decodeObject(data, "routing", "version", "applicationMode", "applicationPaths", "ipv6", "dnsServer")
	if err != nil || len(fields) != 5 {
		return Error{"routing"}
	}
	for _, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return Error{"routing"}
		}
	}
	type plain RoutingPolicy
	var value plain
	if err := json.Unmarshal(data, &value); err != nil {
		return Error{"routing"}
	}
	*p = RoutingPolicy(value)
	return p.Validate()
}

func (p RoutingPolicy) FiltersApplications() bool { return p.ApplicationMode != "all" }
func (p RoutingPolicy) Matches(executable string) bool {
	for _, value := range p.ApplicationPaths {
		if executable == value || strings.HasSuffix(strings.ToLower(value), ".app") && strings.HasPrefix(executable, value+"/") {
			return true
		}
	}
	return false
}
