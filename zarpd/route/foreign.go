package route

import (
	"context"
	"errors"
	"net/netip"
	"strings"
)

type inspectionRunner struct {
	ctx context.Context
	run Runner
}

func (r inspectionRunner) Run(name string, args ...string) (string, error) {
	if err := r.ctx.Err(); err != nil {
		return "", err
	}
	if runner, ok := r.run.(interface {
		RunContext(context.Context, string, ...string) (string, error)
	}); ok {
		return runner.RunContext(r.ctx, name, args...)
	}
	return r.run.Run(name, args...)
}

// InspectPhysical only performs the two read-only checks used by account sockets.
// Their command lifetime is part of the requesting dial, including cancellation.
func (r *Router) InspectPhysical(ctx context.Context, v6 bool) (*Physical, error) {
	reader := New(inspectionRunner{ctx: ctx, run: r.run})
	foreign, err := reader.HasForeignTunnelRoutes("")
	if err != nil || foreign {
		return nil, errors.New("foreign or unknown tunnel routes")
	}
	return reader.CurrentDefaultFamily(v6)
}

// HasForeignTunnelRoutes is a read-only check before binding server sockets to
// a physical interface. A VPN can own /1 or host routes without replacing the
// ordinary default route. Ignore only Darwin's dormant link-local metadata.
func (r *Router) HasForeignTunnelRoutes(ownedInterface string) (bool, error) {
	output, err := r.run.Run("/usr/sbin/netstat", "-rn")
	if err != nil || !strings.Contains(output, "Destination") {
		return false, errors.New("cannot inspect active tunnel routes")
	}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		foreign := false
		for _, field := range fields {
			if strings.HasPrefix(field, "utun") && field != ownedInterface {
				foreign = true
				break
			}
		}
		if !foreign {
			continue
		}
		destination := fields[0]
		address := strings.Split(strings.Split(destination, "/")[0], "%")[0]
		if ip, err := netip.ParseAddr(address); err == nil && ip.Is6() && (ip.IsLinkLocalUnicast() || ip.IsMulticast()) {
			continue
		}
		return true, nil
	}
	return false, nil
}

func (r *Router) UsesInterface(destination, interfaceName string) (bool, error) {
	actual, err := r.routeInterface(destination, true)
	return err == nil && actual == interfaceName, err
}
