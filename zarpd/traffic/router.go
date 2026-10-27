// Package traffic selects a server or a physically bound direct socket per original flow.
package traffic

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/feg55/zarp-macos/zarpd/connection"
	"github.com/feg55/zarp-macos/zarpd/tunproxy"
)

type Owner struct {
	PID        int
	Executable string
}
type OwnerResolver interface {
	Owner(context.Context, tunproxy.Flow) (Owner, error)
}
type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type Config struct {
	Policy            connection.RoutingPolicy
	Proxy, Direct     Dialer
	Owners            OwnerResolver
	HealthPID         int
	HealthDestination netip.AddrPort
	OverrideDNS       bool
}

type Router struct{ config Config }

func New(config Config) (*Router, error) {
	if config.Policy.Validate() != nil || config.Proxy == nil || config.Policy.FiltersApplications() && (config.Direct == nil || config.Owners == nil) {
		return nil, errors.New("invalid server routing configuration")
	}
	config.Policy.ApplicationPaths = append([]string(nil), config.Policy.ApplicationPaths...)
	return &Router{config}, nil
}

func (r *Router) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, errors.New("original flow metadata is required")
}

func (r *Router) DialFlow(ctx context.Context, flow tunproxy.Flow) (net.Conn, error) {
	if flow.Network != "tcp" && flow.Network != "udp" || !flow.Source.IsValid() || !flow.Destination.IsValid() || flow.Destination.Port() == 0 {
		return nil, errors.New("invalid routed flow")
	}
	c := r.config
	// System DNS is shared by applications. An explicit override uses the server
	// for all ordinary DNS traffic, including the system resolver's own process.
	if c.OverrideDNS && flow.Destination.Port() == 53 {
		return c.Proxy.DialContext(ctx, flow.Network, netip.AddrPortFrom(netip.MustParseAddr(c.Policy.DNSServer), 53).String())
	}
	proxy := true
	if c.Policy.FiltersApplications() {
		owner, err := c.Owners.Owner(ctx, flow)
		if err != nil || owner.PID <= 0 || owner.Executable == "" {
			return nil, errors.New("application ownership could not be established")
		}
		// Only the daemon's own exact HTTPS measurement flow bypasses app rules.
		health := owner.PID == c.HealthPID && flow.Network == "tcp" && flow.Destination == c.HealthDestination
		if !health {
			matched := c.Policy.Matches(owner.Executable)
			proxy = c.Policy.ApplicationMode == "include" && matched || c.Policy.ApplicationMode == "exclude" && !matched
		}
	}
	if !proxy {
		return c.Direct.DialContext(ctx, flow.Network, flow.Destination.String())
	}
	if flow.Destination.Addr().Is6() && !c.Policy.IPv6 {
		return nil, errors.New("IPv6 through the server is disabled")
	}
	return c.Proxy.DialContext(ctx, flow.Network, flow.Destination.String())
}
