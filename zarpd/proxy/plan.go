// Package proxy contains the bounded external-engine foundation. Only loopback
// plans are currently executable. It is not registered with production IPC.
package proxy

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"
)

type Engine string

const (
	SingBox Engine = "sing-box"
	Xray    Engine = "xray"
)

type Protocol string

type HTTPTransport string

const (
	WebSocket   HTTPTransport = "ws"
	GRPC        HTTPTransport = "grpc"
	HTTPUpgrade HTTPTransport = "httpupgrade"
)

const (
	VLESSTLS     Protocol = "vless-tls"
	VLESSReality Protocol = "vless-reality"
	TrojanTLS    Protocol = "trojan-tls"
	Hysteria2TLS Protocol = "hysteria2-tls"
	XHTTPH2      Protocol = "vless-xhttp-h2"
	XHTTPH3      Protocol = "vless-xhttp-h3"
)

// LoopbackPlan is trusted program data, not an IPC request. No binary path,
// shell, argv, raw configuration, TUN, DNS or filesystem setting is represented.
// Pin hashes public-key DER for sing-box and certificate DER for Xray.
type LoopbackPlan struct {
	Engine                           Engine
	Protocol                         Protocol
	Target, Relay, Listen            netip.AddrPort
	ServerName, Pin                  string
	Credential                       string
	RelayUser, RelayPassword         string
	ProbeUser, ProbePassword         string
	HTTPTransport                    HTTPTransport
	Path, HostHeader, ServiceName    string
	Flow, Fingerprint                string
	RealityPublicKey, RealityShortID string
	ObfsPassword                     string
}

func (LoopbackPlan) String() string   { return "LoopbackPlan(redacted)" }
func (LoopbackPlan) GoString() string { return "LoopbackPlan(redacted)" }

type Code string

const (
	InvalidPlan          Code = "invalid_plan"
	InvalidLimits        Code = "invalid_limits"
	BinaryUnavailable    Code = "binary_unavailable"
	BinaryIntegrity      Code = "binary_integrity"
	BinarySignature      Code = "binary_signature"
	InvalidInventory     Code = "invalid_inventory"
	VersionMismatch      Code = "version_mismatch"
	Configuration        Code = "configuration_rejected"
	Startup              Code = "startup_failed"
	Readiness            Code = "readiness_failed"
	Cancelled            Code = "cancelled"
	Cleanup              Code = "cleanup_failed"
	Inactive             Code = "runtime_inactive"
	Busy                 Code = "runtime_busy"
	InvalidControl       Code = "invalid_guardian_control"
	ControlLost          Code = "guardian_control_lost"
	OwnershipUnsupported Code = "ownership_unsupported"
)

type Error struct{ Code Code }

func (e Error) Error() string { return "backend: " + string(e.Code) }

func validText(value string, limit int) bool {
	return len(value) > 0 && len(value) <= limit && utf8.ValidString(value) && !strings.ContainsFunc(value, unicode.IsControl)
}

func validName(value string) bool {
	if len(value) == 0 || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func (p LoopbackPlan) validate() error {
	for _, address := range []netip.AddrPort{p.Target, p.Relay, p.Listen} {
		if !address.IsValid() || !address.Addr().IsLoopback() || address.Addr().Zone() != "" || address.Port() == 0 {
			return Error{InvalidPlan}
		}
	}
	if p.Listen.Addr() != netip.MustParseAddr("127.0.0.1") || p.Relay.Addr() != p.Listen.Addr() ||
		p.Listen == p.Relay || p.Listen == p.Target || p.Relay == p.Target || !validName(p.ServerName) {
		return Error{InvalidPlan}
	}
	for _, value := range []string{p.RelayUser, p.RelayPassword, p.ProbeUser, p.ProbePassword} {
		if !validText(value, 255) {
			return Error{InvalidPlan}
		}
	}
	if !validText(p.Credential, 2048) {
		return Error{InvalidPlan}
	}
	if p.Flow != "" && (p.Engine != SingBox || (p.Protocol != VLESSTLS && p.Protocol != VLESSReality) ||
		p.HTTPTransport != "" || p.Flow != "xtls-rprx-vision") {
		return Error{InvalidPlan}
	}
	if p.ObfsPassword != "" && (p.Engine != SingBox || p.Protocol != Hysteria2TLS || !validText(p.ObfsPassword, 4096)) {
		return Error{InvalidPlan}
	}
	if p.Protocol == VLESSReality {
		raw, err := base64.RawURLEncoding.DecodeString(p.RealityPublicKey)
		short, shortErr := hex.DecodeString(p.RealityShortID)
		if p.Engine != SingBox || p.HTTPTransport != "" || p.Pin != "" || p.Fingerprint != "chrome" ||
			err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != p.RealityPublicKey ||
			shortErr != nil || len(short) > 8 {
			return Error{InvalidPlan}
		}
	} else if p.RealityPublicKey != "" || p.RealityShortID != "" {
		return Error{InvalidPlan}
	}
	if p.Fingerprint != "" && (p.Engine != SingBox || p.Fingerprint != "chrome" ||
		(p.Protocol != VLESSTLS && p.Protocol != VLESSReality && p.Protocol != TrojanTLS)) {
		return Error{InvalidPlan}
	}
	if p.HTTPTransport != "" {
		if p.Engine != SingBox || (p.Protocol != VLESSTLS && p.Protocol != TrojanTLS) {
			return Error{InvalidPlan}
		}
		switch p.HTTPTransport {
		case WebSocket, HTTPUpgrade:
			if p.ServiceName != "" || p.Path != "" && (!strings.HasPrefix(p.Path, "/") || !validText(p.Path, 2048)) ||
				p.HostHeader != "" && !validName(p.HostHeader) {
				return Error{InvalidPlan}
			}
		case GRPC:
			if p.Path != "" || p.HostHeader != "" || p.ServiceName != "" && !validText(p.ServiceName, 256) {
				return Error{InvalidPlan}
			}
		default:
			return Error{InvalidPlan}
		}
	} else if p.Path != "" || p.HostHeader != "" || p.ServiceName != "" {
		return Error{InvalidPlan}
	}
	if p.Protocol != TrojanTLS && p.Protocol != Hysteria2TLS {
		if len(p.Credential) != 36 || p.Credential[8] != '-' || p.Credential[13] != '-' ||
			p.Credential[18] != '-' || p.Credential[23] != '-' {
			return Error{InvalidPlan}
		}
		if raw, err := hex.DecodeString(strings.ReplaceAll(p.Credential, "-", "")); err != nil || len(raw) != 16 {
			return Error{InvalidPlan}
		}
	}
	switch p.Engine {
	case SingBox:
		if p.Protocol != VLESSTLS && p.Protocol != VLESSReality && p.Protocol != TrojanTLS && p.Protocol != Hysteria2TLS {
			return Error{InvalidPlan}
		}
		if raw, err := base64.StdEncoding.DecodeString(p.Pin); p.Protocol != VLESSReality && (err != nil || len(raw) != 32 || base64.StdEncoding.EncodeToString(raw) != p.Pin) {
			return Error{InvalidPlan}
		}
	case Xray:
		if p.Protocol != VLESSTLS && p.Protocol != XHTTPH2 && p.Protocol != XHTTPH3 {
			return Error{InvalidPlan}
		}
		if raw, err := hex.DecodeString(p.Pin); err != nil || len(raw) != 32 {
			return Error{InvalidPlan}
		}
	default:
		return Error{InvalidPlan}
	}
	return nil
}

func (p LoopbackPlan) compile() ([]byte, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	var config map[string]any
	if p.Engine == SingBox {
		protocol, credentialField, alpn := "vless", "uuid", []string{"http/1.1"}
		if p.Protocol == TrojanTLS {
			protocol, credentialField = "trojan", "password"
		} else if p.Protocol == Hysteria2TLS {
			protocol, credentialField, alpn = "hysteria2", "password", []string{"h3"}
		}
		if p.HTTPTransport == GRPC {
			alpn = []string{"h2"}
		}
		if p.Protocol == VLESSReality {
			alpn = []string{"h2", "http/1.1"}
		}
		config = map[string]any{
			"log": map[string]any{"disabled": true},
			"inbounds": []any{map[string]any{"type": "socks", "listen": p.Listen.Addr().String(), "listen_port": p.Listen.Port(),
				"users": []any{map[string]any{"username": p.ProbeUser, "password": p.ProbePassword}}}},
			"outbounds": []any{map[string]any{"type": protocol, "tag": "server", "server": p.Target.Addr().String(),
				"server_port": p.Target.Port(), credentialField: p.Credential, "detour": "outer-relay",
				"tls": map[string]any{"enabled": true, "server_name": p.ServerName, "alpn": alpn,
					"certificate_public_key_sha256": []string{p.Pin}}},
				map[string]any{"type": "socks", "tag": "outer-relay", "server": p.Relay.Addr().String(), "server_port": p.Relay.Port(),
					"version": "5", "username": p.RelayUser, "password": p.RelayPassword}},
			"route": map[string]any{"final": "server"},
		}
		outbound := config["outbounds"].([]any)[0].(map[string]any)
		if p.Flow != "" {
			outbound["flow"] = p.Flow
		}
		if p.ObfsPassword != "" {
			outbound["obfs"] = map[string]any{"type": "salamander", "password": p.ObfsPassword}
		}
		if p.Fingerprint != "" {
			outbound["tls"].(map[string]any)["utls"] = map[string]any{"enabled": true, "fingerprint": p.Fingerprint}
		}
		if p.Protocol == VLESSReality {
			tlsOptions := outbound["tls"].(map[string]any)
			delete(tlsOptions, "certificate_public_key_sha256")
			tlsOptions["reality"] = map[string]any{"enabled": true, "public_key": p.RealityPublicKey, "short_id": p.RealityShortID}
		}
		if p.HTTPTransport != "" {
			transport := map[string]any{"type": string(p.HTTPTransport)}
			if p.HTTPTransport == GRPC {
				transport["service_name"] = p.ServiceName
			} else {
				path := p.Path
				if path == "" {
					path = "/"
				}
				transport["path"] = path
				if p.HostHeader != "" {
					if p.HTTPTransport == WebSocket {
						transport["headers"] = map[string]string{"Host": p.HostHeader}
					} else {
						transport["host"] = p.HostHeader
					}
				}
			}
			config["outbounds"].([]any)[0].(map[string]any)["transport"] = transport
		}
	} else {
		network, alpn := "raw", []string{"http/1.1"}
		if p.Protocol == XHTTPH2 {
			network, alpn = "xhttp", []string{"h2"}
		} else if p.Protocol == XHTTPH3 {
			network, alpn = "xhttp", []string{"h3"}
		}
		stream := map[string]any{"network": network, "security": "tls", "sockopt": map[string]any{"dialerProxy": "outer-relay"},
			"tlsSettings": map[string]any{"serverName": p.ServerName, "alpn": alpn, "pinnedPeerCertSha256": p.Pin, "disableSystemRoot": true}}
		if network == "xhttp" {
			stream["xhttpSettings"] = map[string]any{"path": "/private-poc", "mode": "stream-one"}
		}
		config = map[string]any{
			"log": map[string]any{"loglevel": "none"},
			"inbounds": []any{map[string]any{"listen": p.Listen.Addr().String(), "port": p.Listen.Port(), "protocol": "socks",
				"settings": map[string]any{"auth": "password", "accounts": []any{map[string]any{"user": p.ProbeUser, "pass": p.ProbePassword}}, "udp": true, "ip": p.Listen.Addr().String()}}},
			"outbounds": []any{map[string]any{"tag": "server", "protocol": "vless", "settings": map[string]any{
				"vnext": []any{map[string]any{"address": p.Target.Addr().String(), "port": p.Target.Port(),
					"users": []any{map[string]any{"id": p.Credential, "encryption": "none"}}}}}, "streamSettings": stream},
				map[string]any{"tag": "outer-relay", "protocol": "socks", "settings": map[string]any{
					"address": p.Relay.Addr().String(), "port": p.Relay.Port(), "user": p.RelayUser, "pass": p.RelayPassword}}},
		}
	}
	data, err := json.Marshal(config)
	if err != nil || len(data) > 32768 {
		return nil, Error{InvalidPlan}
	}
	return data, nil
}
