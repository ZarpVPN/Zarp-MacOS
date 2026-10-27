package connection

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type vector struct {
	Name               string `json:"name"`
	JSON               string `json:"json"`
	ID                 string `json:"id"`
	ErrorField         Field  `json:"errorField"`
	ServerCapabilities bool   `json:"serverCapabilities"`
}

func TestSharedSwiftGoProfileAndRequestVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "connection-contracts.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Profiles []vector
		Requests []vector
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, v := range fixture.Profiles {
		t.Run("profile/"+v.Name, func(t *testing.T) {
			p, err := DecodeProfile([]byte(v.JSON))
			if v.ErrorField != "" {
				if err != (Error{v.ErrorField}) {
					t.Fatalf("wanted field %s, received %v", v.ErrorField, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if p.ID() != v.ID {
				t.Fatal("Swift/Go executable fingerprint differs")
			}
			raw, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			copy, err := DecodeProfile(raw)
			if err != nil || copy.ID() != p.ID() {
				t.Fatal("round trip lost executable configuration")
			}
			if strings.Contains(fmt.Sprintf("%v %#v", p, p), p.Credential.Value) {
				t.Fatal("profile display disclosed credentials")
			}
		})
	}
	for _, v := range fixture.Requests {
		t.Run("request/"+v.Name, func(t *testing.T) {
			capabilities := CurrentWarpOnly()
			if v.ServerCapabilities {
				capabilities.Modes = append(capabilities.Modes, Server)
				capabilities.Protocols = []string{"vless", "trojan", "hysteria2"}
			}
			_, err := DecodeRequest([]byte(v.JSON), capabilities)
			if v.ErrorField != "" {
				if err != (Error{v.ErrorField}) {
					t.Fatalf("wanted field %s, received %v", v.ErrorField, err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStrictBoundariesRedactMalformedInputAndRejectUnicodeReplacement(t *testing.T) {
	for _, data := range [][]byte{
		[]byte(`{"unknown":"\ud800"}`), []byte(`{"unknown":"\udc00"}`),
		[]byte("{\"unknown\":\"\xff\"}"), []byte(strings.Repeat("[", 40) + "0" + strings.Repeat("]", 40)),
		[]byte("private-credential"), []byte(strings.Repeat("A", MaxProfileBytes+1)),
	} {
		if _, err := DecodeProfile(data); err == nil || strings.Contains(err.Error(), "private-credential") {
			t.Fatal("invalid profile accepted or disclosed input")
		}
	}
	if _, err := DecodeRequest([]byte(strings.Repeat("A", MaxRequestBytes+1)), CurrentWarpOnly()); err == nil {
		t.Fatal("oversized request accepted")
	}
	if !strictJSON([]byte(`{"label":"\ud83d\ude00","literal":"\\ud800"}`)) {
		t.Fatal("valid paired or literal Unicode was refused")
	}
}

func TestProfileIdentityBindsCredentialsAndTransportButNotLabel(t *testing.T) {
	p := Profile{Host: "proxy.example", Port: 443, Protocol: "trojan", Credential: Credential{"password", "test-only"}, Transport: "tcp", Security: "tls", Flow: "none"}
	id := p.ID()
	p.Label = "Renamed"
	if p.ID() != id {
		t.Fatal("label invalidated identity")
	}
	p.Credential.Value = "different-test-only"
	if p.ID() == id {
		t.Fatal("changed credential retained identity")
	}
	p.Credential.Value = "test-only"
	p.Transport = "ws"
	path := "/socket"
	p.Path = &path
	if p.ID() == id {
		t.Fatal("changed transport retained identity")
	}
	if Warp.RequiresWarpAccount() != true || Server.RequiresWarpAccount() != false || Warp.ProbeKind() == Server.ProbeKind() {
		t.Fatal("account/probe mode boundary lost")
	}
}

// Both entrypoints are pure data and safe for fuzzing. Errors must stay static.
func FuzzContractInputBoundaries(f *testing.F) {
	for _, seed := range []string{`{}`, `{"host":"proxy.example"}`, `{"version":1,"mode":"warp","probeKind":"warpTrace","strategyId":"direct","options":{}}`, `{"credential":{"kind":"password","value":"\ud800"}}`} {
		f.Add([]byte(seed))
	}
	f.Add([]byte(`{"kind":"subscription","subscriptionURL":"https://subscriptions.example/list?token=test-only"}`))
	f.Add([]byte(`{"host":"proxy.example","port":443,"serverProtocol":"hysteria2","credential":{"kind":"password","value":"test-only"},"transport":"quic","security":"tls","obfs":"salamander","obfsPassword":"test-only"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, profileErr := DecodeProfile(data)
		_, requestErr := DecodeRequest(data, CurrentWarpOnly())
		_, sourceErr := DecodeSource(data)
		for _, err := range []error{profileErr, requestErr, sourceErr} {
			if err != nil {
				contract, ok := err.(Error)
				if !ok {
					t.Fatal("raw decoder error escaped contract")
				}
				known := []Field{"version", "mode", "profile", "parameters", "credential", "label", "host", "port", "serverProtocol",
					"transport", "security", "serverName", "alpn", "flow", "path", "hostHeader", "serviceName", "timeout", "routing",
					"plain", "capabilities", "probeKind", "strategyId"}
				known = append(known, "fingerprint", "publicKey", "shortId", "obfs", "obfsPassword")
				known = append(known, "source", "sourceURL")
				if !contains(known, contract.Field) {
					t.Fatal("untrusted field name escaped into diagnostics")
				}
			}
		}
	})
}
