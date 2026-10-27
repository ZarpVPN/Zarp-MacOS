package connection

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestApplicationPolicyBundlesAndStrictWireValidation(t *testing.T) {
	p := DefaultRoutingPolicy()
	p.ApplicationMode = "include"
	p.ApplicationPaths = []string{"/Applications/Browser.app", "/usr/bin/curl"}
	if p.Validate() != nil || !p.Matches("/Applications/Browser.app/Contents/Frameworks/Helper.app/Contents/MacOS/Helper") || !p.Matches("/usr/bin/curl") || p.Matches("/Applications/Browser.app.evil/Contents/MacOS/Browser") || p.Matches("/usr/bin/curl-other") {
		t.Fatal("incorrect application boundary")
	}
	data, _ := json.Marshal(p)
	var decoded RoutingPolicy
	if json.Unmarshal(data, &decoded) != nil {
		t.Fatal("typed policy did not round-trip")
	}
	for _, raw := range []string{
		strings.Replace(string(data), `"ipv6":true`, `"ipv6":null`, 1),
		strings.Replace(string(data), `"applicationPaths":["/Applications/Browser.app","/usr/bin/curl"]`, `"applicationPaths":null`, 1),
		strings.TrimSuffix(string(data), "}") + `,"command":"private-test-secret"}`,
		strings.Replace(string(data), `"version":1`, `"version":2`, 1),
	} {
		if err := json.Unmarshal([]byte(raw), &decoded); err == nil || strings.Contains(err.Error(), "private-test-secret") {
			t.Fatal("invalid policy accepted or private input echoed")
		}
	}
}

func TestPolicyRejectsTraversalInvalidDNSAndEmptyInclude(t *testing.T) {
	for _, value := range []string{"/", "relative.app", "/Applications/../Browser.app", "/Applications//Browser.app", "/Applications/Browser.app/", "/Applications/Bad\n.app"} {
		p := DefaultRoutingPolicy()
		p.ApplicationPaths = []string{value}
		if p.Validate() == nil {
			t.Fatal("unsafe application path accepted")
		}
	}
	for _, value := range []string{"127.0.0.1", "::1", "0.0.0.0", "ff00::1", "fe80::1", "::ffff:7f00:1", "01.1.1.1", "1.1.1.1:53", "resolver.example"} {
		p := DefaultRoutingPolicy()
		p.DNSServer = value
		if p.Validate() == nil {
			t.Fatal("invalid DNS accepted")
		}
	}
	p := DefaultRoutingPolicy()
	p.ApplicationMode = "include"
	if p.Validate() == nil {
		t.Fatal("empty include policy became an all-app connection")
	}
	p.ApplicationMode = "all"
	p.IPv6 = false
	p.DNSServer = "2606:4700:4700::1111"
	if p.Validate() == nil {
		t.Fatal("IPv6 resolver accepted with IPv6 disabled")
	}
}
