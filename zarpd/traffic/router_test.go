package traffic

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/feg55/zarp-macos/zarpd/connection"
	"github.com/feg55/zarp-macos/zarpd/tunproxy"
)

type recordedDialer struct {
	calls   int
	address string
}

func (d *recordedDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	d.calls++
	d.address = address
	return nil, errors.New("recorded dial")
}

type fixedOwner struct {
	owner Owner
	err   error
}

func (o fixedOwner) Owner(context.Context, tunproxy.Flow) (Owner, error) { return o.owner, o.err }

func TestIncludeExcludeUnknownOwnershipAndHealthFlow(t *testing.T) {
	for _, mode := range []string{"include", "exclude"} {
		for _, selected := range []bool{true, false} {
			p := connection.DefaultRoutingPolicy()
			p.ApplicationMode = mode
			p.ApplicationPaths = []string{"/Applications/Browser.app"}
			path := "/Applications/Other.app/Contents/MacOS/Other"
			if selected {
				path = "/Applications/Browser.app/Contents/Frameworks/Helper.app/Contents/MacOS/Helper"
			}
			proxy, direct := &recordedDialer{}, &recordedDialer{}
			router, err := New(Config{Policy: p, Proxy: proxy, Direct: direct, Owners: fixedOwner{owner: Owner{PID: 7, Executable: path}}})
			if err != nil {
				t.Fatal(err)
			}
			_, _ = router.DialFlow(context.Background(), tunproxy.Flow{Network: "tcp", Source: netip.MustParseAddrPort("10.0.0.2:50000"), Destination: netip.MustParseAddrPort("198.18.1.1:443")})
			wantProxy := mode == "include" && selected || mode == "exclude" && !selected
			if (proxy.calls == 1) != wantProxy || (direct.calls == 1) == wantProxy {
				t.Fatal("wrong application route")
			}
		}
	}
	p := connection.DefaultRoutingPolicy()
	p.ApplicationMode = "include"
	p.ApplicationPaths = []string{"/Applications/Browser.app"}
	for _, pid := range []int{42, 43, 0} {
		proxy, direct := &recordedDialer{}, &recordedDialer{}
		destination := netip.MustParseAddrPort("198.18.1.1:443")
		router, _ := New(Config{Policy: p, Proxy: proxy, Direct: direct, Owners: fixedOwner{owner: Owner{PID: pid, Executable: "/private/daemon"}}, HealthPID: 42, HealthDestination: destination})
		_, _ = router.DialFlow(context.Background(), tunproxy.Flow{Network: "tcp", Source: netip.MustParseAddrPort("10.0.0.2:50000"), Destination: destination})
		if pid == 42 && proxy.calls != 1 || pid == 43 && direct.calls != 1 || pid == 0 && proxy.calls+direct.calls != 0 {
			t.Fatal("health or unknown-process policy was bypassed")
		}
	}
}

func TestDNSUsesConfiguredServerAndDisabledIPv6DoesNotLeak(t *testing.T) {
	p := connection.DefaultRoutingPolicy()
	p.ApplicationMode = "include"
	p.ApplicationPaths = []string{"/Applications/Browser.app"}
	p.IPv6 = false
	p.DNSServer = "9.9.9.9"
	proxy, direct := &recordedDialer{}, &recordedDialer{}
	router, err := New(Config{Policy: p, Proxy: proxy, Direct: direct, Owners: fixedOwner{err: errors.New("unavailable")}, OverrideDNS: true})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = router.DialFlow(context.Background(), tunproxy.Flow{Network: "udp", Source: netip.MustParseAddrPort("10.0.0.2:50000"), Destination: netip.MustParseAddrPort("1.1.1.1:53")})
	if proxy.calls != 1 || proxy.address != "9.9.9.9:53" || direct.calls != 0 {
		t.Fatal("shared DNS did not use the configured server")
	}
	router.config.Owners = fixedOwner{owner: Owner{PID: 7, Executable: "/Applications/Browser.app/Contents/MacOS/Browser"}}
	_, _ = router.DialFlow(context.Background(), tunproxy.Flow{Network: "tcp", Source: netip.MustParseAddrPort("[fd00::2]:50000"), Destination: netip.MustParseAddrPort("[2001:db8::1]:443")})
	if proxy.calls != 1 || direct.calls != 0 {
		t.Fatal("disabled IPv6 leaked into an outbound")
	}
	router.config.Owners = fixedOwner{owner: Owner{PID: 7, Executable: "/Applications/Other.app/Contents/MacOS/Other"}}
	_, _ = router.DialFlow(context.Background(), tunproxy.Flow{Network: "tcp", Source: netip.MustParseAddrPort("[fd00::2]:50000"), Destination: netip.MustParseAddrPort("[2001:db8::1]:443")})
	if direct.calls != 1 {
		t.Fatal("excluded application lost normal IPv6 access")
	}
}
