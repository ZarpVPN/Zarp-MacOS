package proxy

import (
	"net/netip"
	"slices"

	"github.com/feg55/zarp-macos/zarpd/connection"
)

// LoopbackAccess contains trusted test resources, separate from imported server data.
// It cannot name a binary, system interface, route, DNS service or filesystem path.
type LoopbackAccess struct {
	Target, Relay, Listen                              netip.AddrPort
	Pin                                                string
	RelayUser, RelayPassword, ProbeUser, ProbePassword string
}

func (LoopbackAccess) String() string   { return "LoopbackAccess(redacted)" }
func (LoopbackAccess) GoString() string { return "LoopbackAccess(redacted)" }

// PlanFromLoopbackProfile maps the shared profile to the proven sing-box subset.
// Profiles cannot redirect a test to another server or supply raw engine settings.
// Unsupported values fail by field instead of being ignored or defaulted.
// This private PoC entrypoint is not a production server-mode compiler or IPC method.
func PlanFromLoopbackProfile(p connection.Profile, access LoopbackAccess) (LoopbackPlan, error) {
	if err := p.Validate(); err != nil {
		return LoopbackPlan{}, err
	}
	address, err := netip.ParseAddr(p.Host)
	if err != nil || !address.IsLoopback() || address != access.Target.Addr() {
		return LoopbackPlan{}, connection.Error{Field: "host"}
	}
	if p.Port != int(access.Target.Port()) {
		return LoopbackPlan{}, connection.Error{Field: "port"}
	}
	if p.Security == "none" {
		return LoopbackPlan{}, connection.Error{Field: "security"}
	}
	if p.ServerName == nil {
		return LoopbackPlan{}, connection.Error{Field: "serverName"}
	}
	if _, err := netip.ParseAddr(*p.ServerName); err == nil {
		return LoopbackPlan{}, connection.Error{Field: "serverName"}
	}
	plan := LoopbackPlan{Engine: SingBox, Protocol: VLESSTLS, Target: access.Target, Relay: access.Relay, Listen: access.Listen,
		ServerName: *p.ServerName, Credential: p.Credential.Value, Pin: access.Pin,
		RelayUser: access.RelayUser, RelayPassword: access.RelayPassword, ProbeUser: access.ProbeUser, ProbePassword: access.ProbePassword}
	if p.Protocol == "trojan" {
		plan.Protocol = TrojanTLS
	}
	if p.Protocol == "hysteria2" {
		plan.Protocol = Hysteria2TLS
	}
	expectedALPN := []string{"http/1.1"}
	switch p.Transport {
	case "tcp":
	case "ws":
		plan.HTTPTransport = WebSocket
	case "grpc":
		plan.HTTPTransport = GRPC
		expectedALPN = []string{"h2"}
	case "httpUpgrade":
		plan.HTTPTransport = HTTPUpgrade
	case "quic":
		expectedALPN = []string{"h3"}
	default:
		return LoopbackPlan{}, connection.Error{Field: "transport"}
	}
	value := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	plan.Path, plan.HostHeader, plan.ServiceName = value(p.Path), value(p.HostHeader), value(p.ServiceName)
	if p.Flow == "vision" {
		plan.Flow = "xtls-rprx-vision"
	}
	plan.Fingerprint = value(p.Fingerprint)
	if plan.Fingerprint != "" && plan.Fingerprint != "chrome" {
		return LoopbackPlan{}, connection.Error{Field: "fingerprint"}
	}
	if p.Security == "reality" {
		if access.Pin != "" {
			return LoopbackPlan{}, connection.Error{Field: "certificatePin"}
		}
		plan.Protocol, plan.RealityPublicKey, plan.RealityShortID = VLESSReality, value(p.PublicKey), value(p.ShortID)
		expectedALPN = []string{"h2", "http/1.1"}
	}
	if len(p.ALPN) != 0 && !slices.Equal(p.ALPN, expectedALPN) {
		return LoopbackPlan{}, connection.Error{Field: "alpn"}
	}
	plan.ObfsPassword = value(p.ObfsPassword)
	if err := plan.validate(); err != nil {
		return LoopbackPlan{}, err
	}
	return plan, nil
}
