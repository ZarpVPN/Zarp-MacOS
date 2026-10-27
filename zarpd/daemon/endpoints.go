package daemon

import (
	"fmt"
	"net/netip"

	usqueconfig "github.com/Diniboy1123/usque/config"

	"github.com/feg55/zarp-macos/zarpd/ipc"
)

// The WARP endpoint pool that "isolate tests" rotates through — Windows Zarp's Warp.NextEndpoint,
// ported value for value (MasqueIps/MasquePorts there). ZarpEngine hands the daemon an opaque
// "isolated-N" token per test attempt; mapping consecutive Ns onto different (address, port)
// pairs is what makes each test, and above all the independent re-check that earns a strategy its
// ✔✔, genuinely leave from a fresh 5-tuple instead of inheriting whatever a DPI box learned about
// the last one. Before this, the token was ignored and every attempt hit the account's one
// endpoint.
var (
	poolIPs     = []netip.Addr{netip.MustParseAddr("162.159.198.1"), netip.MustParseAddr("162.159.198.2")}
	poolH3Ports = []int{443, 500, 1701, 4500, 4443, 8443}
)

// defaultPort is the WARP endpoints' standard port: UDP/443 for HTTP/3, TCP/443 for HTTP/2.
const defaultPort = 443

// isolatedEndpoint is the n-th pool endpoint: addresses vary fastest, then ports (so consecutive
// attempts differ in address, and only after both addresses have been used does the port move on).
// This rotation is HTTP3-only. HTTP2 uses the account's dedicated TCP endpoint.
func isolatedEndpoint(n int) netip.AddrPort {
	ip := poolIPs[n%len(poolIPs)]
	return netip.AddrPortFrom(ip, uint16(poolH3Ports[(n/len(poolIPs))%len(poolH3Ports)]))
}

// resolveEndpoint decides which WARP endpoint an open request dials. params must already have
// passed OpenParams.Validate.
//
//   - "" — the account's own endpoint (what the official client would use).
//   - "isolated-N" — the N-th endpoint of the rotation pool.
//   - "ip" / "ip:port" — exactly that (already checked against the WARP ranges).
func resolveEndpoint(p ipc.OpenParams, cfg *usqueconfig.Config) (netip.AddrPort, error) {
	h2 := p.Transport == "masqueH2"
	n, isolated := ipc.IsolatedToken(p.Endpoint)
	switch {
	case p.Endpoint == "" || h2 && isolated:
		host := cfg.EndpointV4
		if h2 {
			host = cfg.EndpointH2V4
			if host == "" {
				host = usqueconfig.DefaultEndpointH2V4
			}
		}
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("the account's endpoint %q is not an IP address: %w", host, err)
		}
		return netip.AddrPortFrom(ip.Unmap(), uint16(defaultPort)), nil
	default:
		if isolated {
			return isolatedEndpoint(n), nil
		}
		ip, port, err := ipc.ParseEndpoint(p.Endpoint)
		if err != nil {
			return netip.AddrPort{}, err
		}
		if port == 0 {
			port = defaultPort
		}
		return netip.AddrPortFrom(ip, uint16(port)), nil
	}
}
