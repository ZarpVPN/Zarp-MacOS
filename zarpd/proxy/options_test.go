package proxy

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func TestAdvancedOptionsRejectIgnoredAuthenticationAndInapplicableFields(t *testing.T) {
	plan := func(credential string) LoopbackPlan {
		return LoopbackPlan{Engine: SingBox, Protocol: TrojanTLS, Target: netip.MustParseAddrPort("127.0.0.1:1443"),
			Relay: netip.MustParseAddrPort("127.0.0.1:11080"), Listen: netip.MustParseAddrPort("127.0.0.1:11081"),
			ServerName: "outer.example.test", Pin: base64.StdEncoding.EncodeToString(make([]byte, 32)), Credential: credential,
			RelayUser: "relay", RelayPassword: "private-relay", ProbeUser: "probe", ProbePassword: "private-probe"}
	}
	vless := plan("11111111-2222-4333-a444-555555555555")
	vless.Protocol = VLESSTLS
	vision := vless
	vision.Flow = "xtls-rprx-vision"
	reality := vless
	reality.Protocol, reality.Pin, reality.Fingerprint = VLESSReality, "", "chrome"
	reality.RealityPublicKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
	reality.RealityShortID = "0123456789abcdef"
	salamander := plan("private-test-password")
	salamander.Protocol, salamander.ObfsPassword = Hysteria2TLS, "private-test-obfs-password"
	for _, p := range []LoopbackPlan{vision, reality, salamander} {
		if _, err := p.compile(); err != nil {
			t.Fatal("valid bounded option refused:", err)
		}
		if strings.Contains(fmt.Sprintf("%v %#v", p, p), "private") {
			t.Fatal("advanced plan disclosed secret")
		}
	}
	for _, test := range []struct {
		plan   LoopbackPlan
		change func(*LoopbackPlan)
	}{
		{vision, func(p *LoopbackPlan) { p.Protocol = TrojanTLS }},
		{vision, func(p *LoopbackPlan) { p.Flow = "unknown-private-value" }},
		{vision, func(p *LoopbackPlan) { p.HTTPTransport = GRPC }},
		{vision, func(p *LoopbackPlan) { p.Engine = Xray }},
		{reality, func(p *LoopbackPlan) { p.Pin = strings.Repeat("A", 43) + "=" }},
		{reality, func(p *LoopbackPlan) { p.RealityPublicKey += "=" }},
		{reality, func(p *LoopbackPlan) { p.RealityPublicKey = p.RealityPublicKey[:42] + "F" }},
		{reality, func(p *LoopbackPlan) { p.RealityShortID = "abc" }},
		{reality, func(p *LoopbackPlan) { p.RealityShortID = "001122334455667788" }},
		{reality, func(p *LoopbackPlan) { p.Fingerprint = "unknown-private-value" }},
		{reality, func(p *LoopbackPlan) { p.HTTPTransport = WebSocket }},
		{reality, func(p *LoopbackPlan) { p.Protocol = VLESSTLS }},
		{salamander, func(p *LoopbackPlan) { p.Protocol = TrojanTLS }},
		{salamander, func(p *LoopbackPlan) { p.ObfsPassword = "private\nsecret" }},
		{salamander, func(p *LoopbackPlan) { p.ObfsPassword = strings.Repeat("A", 4097) }},
	} {
		p := test.plan
		test.change(&p)
		if _, err := p.compile(); err != (Error{InvalidPlan}) {
			t.Fatal("unsafe advanced option accepted")
		}
	}
}
