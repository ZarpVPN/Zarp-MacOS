package proxy

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/feg55/zarp-macos/zarpd/connection"
)

func TestSharedProfileCannotRedirectLoopbackOrDiscardUnsupportedOptions(t *testing.T) {
	name := "outer.example.test"
	profile := connection.Profile{Host: "127.0.0.1", Port: 1443, Protocol: "vless",
		Credential: connection.Credential{Kind: "uuid", Value: "11111111-2222-4333-a444-555555555555"},
		Transport:  "tcp", Security: "tls", ServerName: &name, Flow: "vision", ALPN: []string{"http/1.1"}}
	access := LoopbackAccess{Target: netip.MustParseAddrPort("127.0.0.1:1443"), Relay: netip.MustParseAddrPort("127.0.0.1:11080"),
		Listen: netip.MustParseAddrPort("127.0.0.1:11081"), Pin: strings.Repeat("A", 43) + "=",
		RelayUser: "relay", RelayPassword: "private-relay", ProbeUser: "probe", ProbePassword: "private-probe"}
	if _, err := PlanFromLoopbackProfile(profile, access); err != nil {
		t.Fatal("supported shared profile refused:", err)
	}
	if strings.Contains(fmt.Sprintf("%v %#v", access, access), "private") {
		t.Fatal("access display leaked secrets")
	}
	for _, test := range []struct {
		field  connection.Field
		change func(*connection.Profile)
	}{
		{"host", func(p *connection.Profile) { p.Host = "proxy.example" }},
		{"host", func(p *connection.Profile) { p.Host = "127.0.0.2" }},
		{"host", func(p *connection.Profile) { p.Host = "::1" }},
		{"port", func(p *connection.Profile) { p.Port++ }},
		{"alpn", func(p *connection.Profile) { p.ALPN = []string{"h3"} }},
		{"serverName", func(p *connection.Profile) { p.ServerName = nil }},
		{"serverName", func(p *connection.Profile) { value := "127.0.0.1"; p.ServerName = &value }},
		{"fingerprint", func(p *connection.Profile) { value := "firefox"; p.Fingerprint = &value }},
		{"security", func(p *connection.Profile) { p.Security = "none"; p.ServerName = nil; p.ALPN = nil; p.Flow = "none" }},
	} {
		p := profile
		test.change(&p)
		if _, err := PlanFromLoopbackProfile(p, access); err != (connection.Error{Field: test.field}) {
			t.Fatalf("expected field %s, got %v", test.field, err)
		}
	}
}
