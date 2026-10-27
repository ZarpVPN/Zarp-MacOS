package ipc

import "testing"

func TestCustomWarpEndpointContract(t *testing.T) {
	for _, endpoint := range []string{"162.159.198.1:443", "8.8.8.8:8443", "[2606:4700::1]:443"} {
		p := OpenParams{Transport: "masqueH3", Endpoint: endpoint, EndpointPolicy: "customWarp", FakeSteps: []FakeStep{{Blob: "quic_google", Repeats: 1}}}
		if err := p.Validate(); err != nil {
			t.Errorf("public numeric endpoint rejected: %v", err)
		}
	}
	for _, endpoint := range []string{"", "isolated-1", "example.com:443", "127.0.0.1:443", "10.0.0.1:443", "100.64.0.1:443", "[::1]:443", "[fe80::1%en0]:443", "[ff02::1]:443", "8.8.8.8:0", "8.8.8.8:65536"} {
		p := OpenParams{Endpoint: endpoint, EndpointPolicy: "customWarp"}
		if err := p.Validate(); err == nil {
			t.Errorf("invalid endpoint accepted: %q", endpoint)
		}
	}
	for _, policy := range []string{"", "arbitrary"} {
		p := OpenParams{Endpoint: "8.8.8.8:443", EndpointPolicy: policy}
		if err := p.Validate(); err == nil {
			t.Errorf("legacy or unknown policy bypassed WARP range validation")
		}
	}
}
