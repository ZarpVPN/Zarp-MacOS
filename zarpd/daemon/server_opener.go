package daemon

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/feg55/zarp-macos/zarpd/ipc"
	"github.com/feg55/zarp-macos/zarpd/proxy"
	"github.com/feg55/zarp-macos/zarpd/relay"
	"github.com/feg55/zarp-macos/zarpd/route"
	"github.com/feg55/zarp-macos/zarpd/socksclient"
	"github.com/feg55/zarp-macos/zarpd/traffic"
	"github.com/feg55/zarp-macos/zarpd/tunproxy"
	"github.com/feg55/zarp-macos/zarpd/warp"
	"golang.zx2c4.com/wireguard/tun"
)

func (o *RealOpener) ServerAvailable() bool { return o.Backends != nil }
func (o *RealOpener) ApplicationRoutingAvailable() bool {
	return o.ServerAvailable() && traffic.NativeOwnerSupported()
}

func (o *RealOpener) openServer(request context.Context, p ipc.OpenParams) (Conn, OpenInfo, error) {
	if o.Backends == nil || p.Profile == nil {
		return nil, OpenInfo{}, &ipc.ConnError{Code: ipc.CodeUnsupported, Message: "server backends are unavailable"}
	}
	if p.RoutingPolicy != nil && (!p.Persistent || !p.RouteAll || p.RoutingPolicy.Validate() != nil) {
		return nil, OpenInfo{}, &ipc.ConnError{Code: ipc.CodeBadRequest, Message: "invalid server routing policy"}
	}
	refuseForeign := func(own string) error {
		foreign, err := o.Router.HasForeignTunnelRoutes(own)
		if err != nil {
			return err
		}
		if foreign {
			return &ipc.ConnError{Code: ipc.CodeForeignVPN, Message: "another VPN or tunnel is active"}
		}
		return nil
	}
	if err := refuseForeign(""); err != nil {
		return nil, OpenInfo{}, err
	}
	timeout := time.Duration(p.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	startup, stopStartup := context.WithTimeout(request, timeout)
	defer stopStartup()
	profile := *p.Profile
	addresses, err := net.DefaultResolver.LookupNetIP(startup, "ip", profile.Host)
	if err != nil || len(addresses) == 0 {
		return nil, OpenInfo{}, &ipc.ConnError{Code: "server_dns", Message: "server address resolution failed"}
	}
	var target netip.AddrPort
	for _, address := range addresses {
		address = address.Unmap()
		if address.Is4() {
			target = netip.AddrPortFrom(address, uint16(profile.Port))
			break
		}
	}
	if !target.IsValid() {
		target = netip.AddrPortFrom(addresses[0].Unmap(), uint16(profile.Port))
	}
	if target.Addr().IsUnspecified() || target.Addr().IsMulticast() || target.Addr().IsLinkLocalUnicast() {
		return nil, OpenInfo{}, &ipc.ConnError{Code: ipc.CodeBadRequest, Message: "invalid server destination"}
	}
	physical, err := o.Router.CurrentDefaultFamily(target.Addr().Is6())
	if err != nil {
		return nil, OpenInfo{}, err
	}
	if physical.IsTunnel() {
		return nil, OpenInfo{}, &ipc.ConnError{Code: ipc.CodeForeignVPN, Message: "another VPN or tunnel is active"}
	}
	lifetime := o.Lifetime
	if lifetime == nil {
		lifetime = context.Background()
	}
	ctx, cancel := context.WithCancel(lifetime)
	stopRequest := context.AfterFunc(startup, cancel)
	defer stopRequest()
	connection := &serverConn{router: o.Router, measureHost: o.MeasureHost, physical: physical, outerIPv6: target.Addr().Is6(), cancel: cancel, done: make(chan struct{})}
	startupDone := make(chan struct{})
	defer close(startupDone)
	fail := func(err error) (Conn, OpenInfo, error) {
		if errors.Is(err, route.ErrCleanupIncomplete) {
			err = errCleanupIncomplete
		}
		if connection.Close() != nil {
			return nil, OpenInfo{}, errCleanupIncomplete
		}
		return nil, OpenInfo{}, err
	}
	credential := func() (string, error) {
		var data [16]byte
		_, err := rand.Read(data[:])
		return hex.EncodeToString(data[:]), err
	}
	relayUser, err := credential()
	if err != nil {
		return fail(err)
	}
	relayPassword, err := credential()
	if err != nil {
		return fail(err)
	}
	probeUser, err := credential()
	if err != nil {
		return fail(err)
	}
	probePassword, err := credential()
	if err != nil {
		return fail(err)
	}
	outerConfig := relay.OuterConfig{Target: target, ServerName: profile.Host, Username: relayUser, Password: relayPassword, UDP: profile.OuterTransport() == "udp", AllowPlain: p.AllowPlain,
		Dialer: &net.Dialer{Timeout: timeout, Control: physical.Control}, BindUDP: physical.BindUDP}
	if profile.ServerName != nil {
		outerConfig.ServerName = *profile.ServerName
	}
	if _, err := netip.ParseAddr(outerConfig.ServerName); err == nil {
		outerConfig.ServerName = ""
	}
	if profile.ECHConfig != nil {
		outerConfig.ServerName = ""
	}
	if p.TCPDesync != nil {
		mode := warp.DesyncSplit
		if p.TCPDesync.Mode == "disorder" {
			mode = warp.DesyncDisorder
		}
		outerConfig.Desync = &warp.DesyncSpec{Mode: mode, Pos: p.TCPDesync.Positions}
	}
	outerConfig.FakeSteps, err = o.toFakeSteps(p.FakeSteps)
	if err != nil {
		return fail(err)
	}
	connection.outer, err = relay.StartOuter(ctx, outerConfig)
	if err != nil {
		return fail(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return fail(err)
	}
	listen := listener.Addr().(*net.TCPAddr).AddrPort()
	listener.Close()
	plan := proxy.ServerPlan{Profile: profile, Target: target, Relay: connection.outer.Address(), Listen: listen, RelayUser: relayUser, RelayPassword: relayPassword, ProbeUser: probeUser, ProbePassword: probePassword}
	limits := proxy.DefaultLimits()
	limits.Lifetime = time.Minute
	limits.StartupTimeout = min(timeout, 15*time.Second)
	started := time.Now()
	connection.backend, err = o.Backends.StartServer(ctx, plan, limits)
	if err != nil {
		return fail(&ipc.ConnError{Code: "server_backend", Message: "server backend startup failed"})
	}
	access := socksclient.Client{Address: listen, Username: probeUser, Password: probePassword}
	if err = probeServerHTTPS(startup, access, o.MeasureHost); err != nil {
		return fail(&ipc.ConnError{Code: "server_traffic", Message: "server HTTPS verification failed"})
	}
	connectMs := int(time.Since(started).Milliseconds())
	statistics := connection.outer.Statistics()
	if !p.AllowPlain && (statistics.AppliedFlows == 0 || statistics.Connections == 0) {
		return fail(&ipc.ConnError{Code: "strategy_unapplied", Message: "the required outer strategy was not applied"})
	}
	if err = refuseForeign(""); err != nil {
		return fail(err)
	}
	if startup.Err() != nil {
		return fail(startup.Err())
	}
	var frontend tunproxy.Dialer = access
	if p.RoutingPolicy != nil {
		if p.RoutingPolicy.FiltersApplications() {
			if !traffic.NativeOwnerSupported() {
				return fail(&ipc.ConnError{Code: ipc.CodeUnsupported, Message: "application ownership is unavailable"})
			}
			connection.direct4, err = o.Router.CurrentDefaultFamily(false)
			if err != nil || connection.direct4.IsTunnel() {
				return fail(errors.New("physical IPv4 network is unavailable"))
			}
			connection.direct6, _ = o.Router.CurrentDefaultFamily(true)
			if connection.direct6 != nil && connection.direct6.IsTunnel() {
				return fail(&ipc.ConnError{Code: ipc.CodeForeignVPN, Message: "another IPv6 tunnel is active"})
			}
			connection.scoped, err = o.Router.AcquireScopedDirect([]*route.Physical{connection.direct4, connection.direct6}, o.ScopedJournal)
			if err != nil {
				return fail(err)
			}
		}
		measurement, parseErr := netip.ParseAddr(o.MeasureHost)
		if parseErr != nil {
			return fail(errors.New("invalid measurement address"))
		}
		frontend, err = traffic.New(traffic.Config{Policy: *p.RoutingPolicy, Proxy: access, Direct: &serverDirectDialer{owner: connection}, Owners: &traffic.NativeOwners{},
			HealthPID: os.Getpid(), HealthDestination: netip.AddrPortFrom(measurement, 443), OverrideDNS: p.OverrideDNS})
		if err != nil {
			return fail(err)
		}
	}
	connection.bridge, err = tunproxy.New(ctx, frontend, o.MTU)
	if err != nil {
		return fail(err)
	}
	connection.device, err = tun.CreateTUN("utun", o.MTU)
	if err != nil {
		return fail(err)
	}
	connection.name, err = connection.device.Name()
	if err != nil {
		return fail(err)
	}
	if err = o.Router.ConfigureAddress(connection.name, "172.19.0.1"); err != nil {
		return fail(err)
	}
	if err = refuseForeign(connection.name); err != nil {
		return fail(err)
	}
	// The bridge owns no OS interface. The daemon retains the actual utun handle,
	// so daemon death closes it even before the separate backend guardian exits.
	go func() {
		if err := connection.bridge.Run(connection.device); err != nil {
			<-startupDone
			connection.fail(errors.New("server packet forwarding stopped"))
		}
	}()
	info := OpenInfo{Endpoint: target.String(), UtunName: connection.name, ConnectMs: connectMs}
	if p.RouteAll {
		var warnings []string
		configuration := route.FullTunnelConfig{Utun: connection.name, IPv6Addr: "fdfe:dcba:9876::1", OverrideDNS: p.OverrideDNS, Physical: physical, Exclude: target.Addr(), Journal: o.Journal}
		if p.RoutingPolicy != nil {
			configuration.DNSServers = []string{p.RoutingPolicy.DNSServer}
			configuration.RequireDNS = p.OverrideDNS
			configuration.RequireIPv6 = p.RoutingPolicy.FiltersApplications() || !p.RoutingPolicy.IPv6
		}
		connection.full, warnings, err = o.Router.EnableFullTunnel(configuration, o.DNS)
		if err != nil {
			return fail(err)
		}
		info.RouteAll = true
		info.Warnings = warnings
	} else {
		if err = o.Router.AddHostRoute(o.MeasureHost, connection.name); err != nil {
			return fail(err)
		}
		connection.testRoute = true
	}
	// A listener and a pre-TUN probe are insufficient. This request uses the
	// system route into this exact newly owned utun and the userspace bridge.
	if routed, err := o.Router.UsesInterface(o.MeasureHost, connection.name); err != nil || !routed {
		return fail(&ipc.ConnError{Code: "server_tunnel", Message: "server measurement route is unavailable"})
	}
	post := (&TraceMeasurer{RequestTimeout: 5 * time.Second}).MeasureServer(startup, o.MeasureHost, 1)
	if post.Kind != "ok" {
		return fail(&ipc.ConnError{Code: "server_tunnel", Message: "the server tunnel did not pass HTTPS traffic"})
	}
	if routed, err := o.Router.UsesInterface(o.MeasureHost, connection.name); err != nil || !routed {
		return fail(&ipc.ConnError{Code: "server_tunnel", Message: "server measurement route changed"})
	}
	if err := refuseForeign(connection.name); err != nil {
		return fail(err)
	}
	if startup.Err() != nil {
		return fail(startup.Err())
	}
	go connection.monitor(ctx, refuseForeign)
	return connection, info, nil
}

func probeServerHTTPS(ctx context.Context, client socksclient.Client, host string) error {
	transport := &http.Transport{Proxy: nil, DialContext: client.DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 10 * time.Second, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/cdn-cgi/trace", nil)
	if err != nil {
		return err
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return errors.New("private server HTTPS transport failed")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 8193))
	if err != nil || response.StatusCode != 200 || len(data) > 8192 || !strings.Contains(string(data), "ip=") {
		return errors.New("private server HTTPS response failed")
	}
	return nil
}

type serverConn struct {
	name, measureHost string
	device            tun.Device
	bridge            *tunproxy.Bridge
	backend           *proxy.GuardedSession
	outer             *relay.Outer
	physical          *route.Physical
	direct4, direct6  *route.Physical
	scoped            *route.ScopedDirect
	outerIPv6         bool
	router            *route.Router
	full              *route.FullTunnel
	testRoute         bool
	cancel            context.CancelFunc
	done              chan struct{}
	once              sync.Once
	mu                sync.Mutex
	err, cleanupErr   error
}

func (c *serverConn) Name() string          { return c.name }
func (c *serverConn) Done() <-chan struct{} { return c.done }
func (c *serverConn) Err() error            { c.mu.Lock(); defer c.mu.Unlock(); return c.err }
func (c *serverConn) VerifyMeasurementPath() error {
	select {
	case <-c.done:
		return errors.New("server connection ended")
	default:
	}
	if routed, err := c.router.UsesInterface(c.measureHost, c.name); err != nil || !routed {
		return errors.New("server measurement route changed")
	}
	if foreign, err := c.router.HasForeignTunnelRoutes(c.name); err != nil || foreign {
		return errors.New("external tunnel detected")
	}
	return nil
}
func (c *serverConn) fail(err error) {
	c.mu.Lock()
	if c.err == nil {
		c.err = err
	}
	c.mu.Unlock()
	_ = c.Close()
}
func (c *serverConn) monitor(ctx context.Context, guard func(string) error) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-ctx.Done():
			_ = c.Close()
			return
		case <-c.backend.Done():
			c.fail(errors.New("server backend stopped"))
			return
		case <-ticker.C:
			if c.backend.RenewLease() != nil {
				c.fail(errors.New("server backend lease ended"))
				return
			}
			if err := guard(c.name); err != nil {
				c.fail(errors.New("external tunnel or network change detected"))
				return
			}
			if c.scoped != nil {
				if c.scoped.Verify() != nil {
					c.fail(errors.New("application routing physical scope changed"))
					return
				}
				for _, saved := range []*route.Physical{c.direct4, c.direct6} {
					if saved == nil {
						continue
					}
					current, err := c.router.CurrentDefaultFamily(saved.Gateway.To4() == nil)
					if err != nil || current.Interface != saved.Interface || current.Index != saved.Index || !current.Gateway.Equal(saved.Gateway) {
						c.fail(errors.New("application routing physical network changed"))
						return
					}
				}
			}
			current, err := c.router.CurrentDefaultFamily(c.outerIPv6)
			if err != nil || current.Interface != c.physical.Interface || current.Index != c.physical.Index || !current.Gateway.Equal(c.physical.Gateway) {
				c.fail(errors.New("physical network changed"))
				return
			}
		}
	}
}
func (c *serverConn) Close() error {
	c.once.Do(func() {
		defer close(c.done)
		c.cancel()
		var failures []error
		if c.full != nil {
			failures = append(failures, c.full.Disable()...)
		}
		if c.testRoute {
			if _, err := c.router.DeleteRouteIfOurs(c.measureHost, true, c.name); err != nil {
				failures = append(failures, err)
			}
		}
		if c.bridge != nil {
			c.bridge.Stop()
		}
		if c.device != nil {
			if err := c.device.Close(); err != nil {
				failures = append(failures, err)
			}
		}
		if c.bridge != nil {
			c.bridge.Wait()
		}
		if c.scoped != nil {
			if err := c.scoped.Close(); err != nil {
				failures = append(failures, err)
			}
		}
		if c.backend != nil {
			if err := c.backend.Close(); err != nil {
				failures = append(failures, err)
			}
		}
		if c.outer != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			if err := c.outer.CloseBounded(ctx); err != nil {
				failures = append(failures, err)
			}
			cancel()
		}
		if len(failures) > 0 {
			c.cleanupErr = errCleanupIncomplete
		}
	})
	return c.cleanupErr
}

type serverDirectDialer struct{ owner *serverConn }

func (d *serverDirectDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	target, err := netip.ParseAddrPort(address)
	if err != nil || d.owner.scoped == nil {
		return nil, errors.New("direct application route is unavailable")
	}
	physical := d.owner.direct4
	if target.Addr().Is6() {
		physical = d.owner.direct6
	}
	if physical == nil || physical.IsTunnel() || d.owner.scoped.CheckForDial() != nil {
		return nil, errors.New("direct application network changed")
	}
	return (&net.Dialer{Timeout: 15 * time.Second, Control: physical.Control}).DialContext(ctx, network, address)
}
