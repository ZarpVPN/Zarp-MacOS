package proxy

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/netip"
	"strings"

	"github.com/feg55/zarp-macos/zarpd/connection"
)

// ServerPlan contains a validated profile and resources allocated by the daemon.
// Its local ingress/relay never comes from subscription data or public IPC.
type ServerPlan struct {
	Profile                                            connection.Profile
	Target, Relay, Listen                              netip.AddrPort
	RelayUser, RelayPassword, ProbeUser, ProbePassword string
	Pin                                                string // Dedicated loopback-test pin; production uses profile verification.
}

func (ServerPlan) String() string   { return "ServerPlan(redacted)" }
func (ServerPlan) GoString() string { return "ServerPlan(redacted)" }
func (p ServerPlan) engine() Engine {
	if p.Profile.Transport == "xhttp" {
		return Xray
	}
	return SingBox
}
func (p ServerPlan) readiness() LoopbackPlan {
	return LoopbackPlan{Engine: p.engine(), Listen: p.Listen, ProbeUser: p.ProbeUser, ProbePassword: p.ProbePassword}
}
func (p ServerPlan) validate() error {
	if err := p.Profile.Validate(); err != nil {
		return err
	}
	if !p.Target.IsValid() || p.Target.Port() != uint16(p.Profile.Port) || p.Target.Addr().IsUnspecified() || p.Target.Addr().IsMulticast() || p.Target.Addr().Zone() != "" ||
		!p.Relay.IsValid() || p.Relay.Addr() != netip.MustParseAddr("127.0.0.1") || p.Relay.Port() == 0 ||
		!p.Listen.IsValid() || p.Listen.Addr() != p.Relay.Addr() || p.Listen.Port() == 0 || p.Listen == p.Relay {
		return Error{InvalidPlan}
	}
	for _, value := range []string{p.ProbeUser, p.ProbePassword, p.RelayUser, p.RelayPassword} {
		if value == "" || len(value) > 255 {
			return Error{InvalidPlan}
		}
	}
	if p.Profile.Security == "none" {
		return connection.Error{Field: "security"}
	}
	if p.Pin != "" {
		if p.Profile.Security != "tls" {
			return Error{InvalidPlan}
		}
		if p.engine() == SingBox {
			value, err := base64.StdEncoding.DecodeString(p.Pin)
			if err != nil || len(value) != 32 {
				return Error{InvalidPlan}
			}
		} else {
			value, err := hex.DecodeString(p.Pin)
			if err != nil || len(value) != 32 {
				return Error{InvalidPlan}
			}
		}
	}
	return nil
}

func (p ServerPlan) compile() ([]byte, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	profile := p.Profile
	serverName := profile.Host
	if profile.ServerName != nil {
		serverName = *profile.ServerName
	}
	var config map[string]any
	if p.engine() == SingBox {
		tls := map[string]any{"enabled": true, "server_name": serverName}
		if len(profile.ALPN) > 0 {
			tls["alpn"] = profile.ALPN
		}
		if p.Pin != "" {
			tls["certificate_public_key_sha256"] = []string{p.Pin}
		}
		if profile.Fingerprint != nil {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": *profile.Fingerprint}
		}
		if profile.Security == "reality" {
			tls["reality"] = map[string]any{"enabled": true, "public_key": *profile.PublicKey, "short_id": pointerText(profile.ShortID)}
		}
		if profile.ECHConfig != nil {
			raw, _ := base64.StdEncoding.DecodeString(*profile.ECHConfig)
			tls["ech"] = map[string]any{"enabled": true, "config": []string{string(pem.EncodeToMemory(&pem.Block{Type: "ECHCONFIG", Bytes: raw}))}}
		}
		outbound := map[string]any{"type": profile.Protocol, "tag": "server", "server": p.Target.Addr().String(), "server_port": p.Target.Port(), "tls": tls, "detour": "outer-relay"}
		if profile.Protocol == "vless" {
			outbound["uuid"] = profile.Credential.Value
			outbound["packet_encoding"] = "xudp"
			if profile.Flow == "vision" {
				outbound["flow"] = "xtls-rprx-vision"
			}
		} else {
			outbound["password"] = profile.Credential.Value
		}
		if profile.Obfs != nil {
			outbound["obfs"] = map[string]any{"type": *profile.Obfs, "password": *profile.ObfsPassword}
		}
		switch profile.Transport {
		case "ws", "grpc", "httpUpgrade":
			kind := profile.Transport
			if kind == "httpUpgrade" {
				kind = "httpupgrade"
			}
			transport := map[string]any{"type": kind}
			if kind == "grpc" {
				transport["service_name"] = pointerText(profile.ServiceName)
			} else {
				path := pointerText(profile.Path)
				if path == "" {
					path = "/"
				}
				transport["path"] = path
				if profile.HostHeader != nil {
					if kind == "ws" {
						transport["headers"] = map[string]string{"Host": *profile.HostHeader}
					} else {
						transport["host"] = *profile.HostHeader
					}
				}
			}
			outbound["transport"] = transport
		}
		config = map[string]any{"log": map[string]any{"level": "error", "timestamp": false},
			"inbounds":  []any{map[string]any{"type": "socks", "tag": "ingress", "listen": "127.0.0.1", "listen_port": p.Listen.Port(), "users": []any{map[string]string{"username": p.ProbeUser, "password": p.ProbePassword}}}},
			"outbounds": []any{outbound, map[string]any{"type": "socks", "tag": "outer-relay", "server": "127.0.0.1", "server_port": p.Relay.Port(), "username": p.RelayUser, "password": p.RelayPassword, "version": "5"}},
			"route":     map[string]any{"final": "server"}}
	} else {
		tls := map[string]any{"serverName": serverName}
		if len(profile.ALPN) > 0 {
			tls["alpn"] = profile.ALPN
		}
		if profile.Fingerprint != nil {
			tls["fingerprint"] = *profile.Fingerprint
		}
		if p.Pin != "" {
			tls["pinnedPeerCertSha256"] = p.Pin
			tls["disableSystemRoot"] = true
		}
		if profile.ECHConfig != nil {
			tls["echConfigList"] = *profile.ECHConfig
		}
		if len(profile.CertificatePins) > 0 {
			tls["pinnedPeerCertSha256"] = strings.Join(profile.CertificatePins, ",")
		}
		if len(profile.CertificateNames) > 0 {
			tls["verifyPeerCertByName"] = strings.Join(profile.CertificateNames, ",")
		}
		xhttp := map[string]any{"mode": "auto", "path": "/"}
		if profile.XHTTPMode != nil {
			xhttp["mode"] = *profile.XHTTPMode
		}
		if profile.XHTTPPadding != nil {
			xhttp["xPaddingBytes"] = *profile.XHTTPPadding
		}
		if profile.Path != nil {
			xhttp["path"] = *profile.Path
		}
		if profile.HostHeader != nil {
			xhttp["host"] = *profile.HostHeader
		}
		stream := map[string]any{"network": "xhttp", "security": profile.Security, "sockopt": map[string]any{"dialerProxy": "outer-relay"}, "xhttpSettings": xhttp}
		if profile.Security == "reality" {
			reality := map[string]any{"serverName": serverName, "publicKey": *profile.PublicKey, "shortId": pointerText(profile.ShortID), "fingerprint": "chrome"}
			if profile.Fingerprint != nil {
				reality["fingerprint"] = *profile.Fingerprint
			}
			if profile.SpiderX != nil {
				reality["spiderX"] = *profile.SpiderX
			}
			if profile.MLDSAVerify != nil {
				reality["mldsa65Verify"] = *profile.MLDSAVerify
			}
			stream["realitySettings"] = reality
		} else {
			stream["tlsSettings"] = tls
		}
		if profile.XHTTPExtra != nil {
			var extra map[string]any
			if json.Unmarshal([]byte(*profile.XHTTPExtra), &extra) != nil {
				return nil, Error{InvalidPlan}
			}
			if download, ok := extra["downloadSettings"].(map[string]any); ok {
				download["address"] = p.Target.Addr().String()
				download["port"] = p.Target.Port()
				download["network"] = "xhttp"
				download["security"] = profile.Security
				download["sockopt"] = map[string]any{"dialerProxy": "outer-relay"}
				if profile.Security == "tls" {
					download["tlsSettings"] = tls
				} else {
					download["realitySettings"] = stream["realitySettings"]
				}
				if download["xhttpSettings"] == nil {
					secondary := map[string]any{}
					for key, value := range xhttp {
						secondary[key] = value
					}
					download["xhttpSettings"] = secondary
				}
			}
			xhttp["extra"] = extra
		}
		settings := map[string]any{"vnext": []any{map[string]any{"address": p.Target.Addr().String(), "port": p.Target.Port(), "users": []any{map[string]any{"id": profile.Credential.Value, "encryption": "none"}}}}}
		if profile.Protocol == "trojan" {
			settings = map[string]any{"servers": []any{map[string]any{"address": p.Target.Addr().String(), "port": p.Target.Port(), "password": profile.Credential.Value}}}
		}
		config = map[string]any{"log": map[string]any{"loglevel": "none", "access": "none"},
			"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": p.Listen.Port(), "protocol": "socks", "settings": map[string]any{"auth": "password", "accounts": []any{map[string]string{"user": p.ProbeUser, "pass": p.ProbePassword}}, "udp": true, "ip": "127.0.0.1"}}},
			"outbounds": []any{map[string]any{"tag": "server", "protocol": profile.Protocol, "settings": settings, "streamSettings": stream},
				map[string]any{"tag": "outer-relay", "protocol": "socks", "settings": map[string]any{"address": "127.0.0.1", "port": p.Relay.Port(), "user": p.RelayUser, "pass": p.RelayPassword}}}}
	}
	data, err := json.Marshal(config)
	if err != nil || len(data) > 32768 {
		return nil, Error{InvalidPlan}
	}
	return data, nil
}

func pointerText(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func (s *Supervisor) StartServer(ctx context.Context, plan ServerPlan, limits Limits) (*Session, error) {
	data, err := plan.compile()
	if err != nil {
		return nil, err
	}
	return s.startPrepared(ctx, plan.readiness(), data, limits)
}

// NewParentServerSupervisor is used only inside the separately pinned guardian.
// Engine processes retain finite leases; an open inherited control pipe permits
// renewal while its daemon lives, without the PoC's fixed two-minute lifetime.
func NewParentServerSupervisor(root string) (*Supervisor, error) {
	s, err := NewParentSessionSupervisor(root)
	if err == nil {
		s.serverRuntime = true
	}
	return s, err
}
