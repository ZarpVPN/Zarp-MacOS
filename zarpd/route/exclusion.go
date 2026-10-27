package route

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Exclusion routes: keeping the tunnel's own control connection off the tunnel.
//
// Once the full-tunnel /1 routes are in, *everything* — including the QUIC/TCP connection that
// carries the tunnel itself — would be routed into the tunnel, which cannot work. The control socket
// is bound to the physical interface (IP_BOUND_IF), and that was meant to be enough; the first run on
// a real Mac showed it is not: on the machine's primary network service there is no interface-scoped
// default route, so a bound socket falls back to the ordinary routing table, finds the more specific
// /1 route through the utun, rejects it as the wrong interface and gives up with ENETUNREACH — the
// MASQUE session died within a millisecond of the routes going in. The fix is the one wg-quick and
// OpenVPN use: a host route for the endpoint through the physical gateway, which is more specific
// than any /1 and so wins for both bound and unbound lookups.
//
// Unlike the /1 routes, a host route via a gateway is not tied to the utun: it would survive the
// daemon being killed. Left behind it is harmless until the network changes, and then it would point
// the WARP endpoint at a gateway that no longer exists. So every such route is written to a journal
// *before* it is added and removed from it after it is deleted, and whatever the journal still lists
// at the next daemon start is deleted then (Journal.Recover) — the same discipline as the DNS backup.

type journalEntry struct {
	Host      string `json:"host"`
	Gateway   string `json:"gateway,omitempty"`
	Interface string `json:"interface"`
}

// Journal is the on-disk record of exclusion routes currently installed.
type Journal struct {
	path string
	mu   sync.Mutex
}

// NewJournal returns a Journal stored at path (e.g. /var/db/zarpd/exclusions.json — root-only).
func NewJournal(path string) *Journal { return &Journal{path: path} }

func (j *Journal) readLocked() ([]journalEntry, error) {
	data, err := os.ReadFile(j.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var entries []journalEntry
	if err := json.Unmarshal(data, &entries); err != nil || entries == nil {
		return nil, errors.Join(ErrCleanupIncomplete, errors.New("unreadable route recovery data retained"))
	}
	for _, entry := range entries {
		address, err := netip.ParseAddr(entry.Host)
		if err != nil || address.Zone() != "" || entry.Interface == "" || len(entry.Interface) > 64 || strings.ContainsAny(entry.Interface, " \t\r\n\x00") {
			return nil, errors.Join(ErrCleanupIncomplete, errors.New("invalid route recovery data retained"))
		}
		if entry.Gateway != "" {
			gateway, err := netip.ParseAddr(entry.Gateway)
			if err != nil || gateway.Is4() != address.Is4() {
				return nil, errors.Join(ErrCleanupIncomplete, errors.New("invalid route recovery data retained"))
			}
		}
	}
	return entries, nil
}

func (j *Journal) writeLocked(entries []journalEntry) error {
	if len(entries) == 0 {
		if err := os.Remove(j.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(j.path), 0o700); err != nil {
		return err
	}
	tmp := j.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, j.path)
}

func (j *Journal) add(e journalEntry) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	entries, err := j.readLocked()
	if err != nil {
		return err
	}
	for _, x := range entries {
		if x == e {
			return nil
		}
	}
	return j.writeLocked(append(entries, e))
}

func (j *Journal) remove(host string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	entries, err := j.readLocked()
	if err != nil {
		return err
	}
	kept := entries[:0]
	for _, x := range entries {
		if x.Host != host {
			kept = append(kept, x)
		}
	}
	return j.writeLocked(kept)
}

// Recover deletes every exclusion route a previous run left behind (the journal still lists it only
// if that run died before cleaning up). Failed entries and unreadable data stay
// available for recovery. Call once at startup; serialize against add/remove.
func (j *Journal) Recover(r *Router) []error {
	j.mu.Lock()
	defer j.mu.Unlock()
	entries, err := j.readLocked()
	var errs []error
	if err != nil {
		return []error{err}
	}
	var retained []journalEntry
	for _, e := range entries {
		if _, derr := r.deleteExclusion(e); derr != nil {
			errs = append(errs, derr)
			retained = append(retained, e)
		}
	}
	if err := j.writeLocked(retained); err != nil {
		errs = append(errs, err)
	}
	return errs
}

// AddExclusion pins host (an IPv4 address — the WARP endpoint) to the physical network: traffic to
// it keeps using phys's gateway (or interface, when the default route has no gateway) whatever
// other routes are added later. It returns the function that removes the route again.
//
// If a route for host already exists through the same interface it is left as it is and not
// removed afterwards (it isn't ours); one through a different interface is an error, because that
// is exactly the situation the exclusion exists to prevent.
func (r *Router) AddExclusion(host netip.Addr, phys *Physical, journal *Journal) (undo func() error, err error) {
	host = host.Unmap()
	if !host.IsValid() || host.Zone() != "" {
		return nil, fmt.Errorf("invalid exclusion address")
	}
	if phys == nil || phys.Interface == "" {
		return nil, errors.New("exclusion route: the physical interface is unknown")
	}
	entry := journalEntry{Host: host.String(), Interface: phys.Interface}
	args := []string{"-n", "add", "-host", entry.Host}
	if host.Is6() {
		args = []string{"-n", "add", "-inet6", "-host", entry.Host}
	}
	if phys.Gateway != nil && !phys.Gateway.IsUnspecified() {
		entry.Gateway = phys.Gateway.String()
		if host.Is6() && phys.GatewayZone != "" {
			entry.Gateway += "%" + phys.GatewayZone
		}
		args = append(args, entry.Gateway)
	} else {
		args = append(args, "-interface", phys.Interface)
	}

	// Recorded first: a crash between "route added" and "journal written" would leave a route
	// nobody knows to remove.
	if journal != nil {
		if err := journal.add(entry); err != nil {
			return nil, fmt.Errorf("exclusion route: saving the route journal: %w", err)
		}
	}
	forget := func() error {
		if journal != nil {
			if err := journal.remove(entry.Host); err != nil {
				return errors.Join(ErrCleanupIncomplete, err)
			}
		}
		return nil
	}

	out, rerr := r.run.Run(routeBin, args...)
	owned := true
	if rerr != nil {
		if !strings.Contains(out, "File exists") {
			return nil, errors.Join(fmt.Errorf("exclusion route for %s: %w: %s", entry.Host, rerr, strings.TrimSpace(out)), forget())
		}
		iface, gerr := r.routeInterface(entry.Host, true)
		if gerr != nil || iface != phys.Interface {
			return nil, errors.Join(fmt.Errorf("exclusion route for %s: a route through %q already exists", entry.Host, iface), forget())
		}
		owned = false // somebody else's route, through the right interface: use it, leave it
		if err := forget(); err != nil {
			return nil, err
		}
	}
	return func() error {
		if !owned {
			return nil
		}
		if _, err := r.deleteExclusion(entry); err != nil {
			return err // Retain this owned route's recovery record on failure.
		}
		return forget()
	}, nil
}

// deleteExclusion removes the host route described by e. A route that's already gone (or never
// existed) is not an error. `route delete -host` removes only an exact host route, so it can never
// take a default or /1 route with it.
func (r *Router) deleteExclusion(e journalEntry) (bool, error) {
	query := []string{"-n", "get", "-host", e.Host}
	if ip, err := netip.ParseAddr(e.Host); err == nil && ip.Is6() {
		query = []string{"-n", "get", "-inet6", "-host", e.Host}
	}
	current, qerr := r.run.Run(routeBin, query...)
	if qerr != nil {
		if strings.Contains(current, "not in table") {
			return false, nil
		}
		return false, fmt.Errorf("checking exclusion ownership: %w", qerr)
	}
	fields := parseRouteGet(current)
	if fields["interface"] != e.Interface || fields["destination"] != e.Host || !strings.Contains(fields["flags"], "HOST") {
		return false, nil
	}
	if e.Gateway != "" && fields["gateway"] != e.Gateway {
		return false, nil
	}

	args := []string{"-n", "delete", "-host", e.Host}
	if ip, err := netip.ParseAddr(e.Host); err == nil && ip.Is6() {
		args = []string{"-n", "delete", "-inet6", "-host", e.Host}
	}
	out, err := r.run.Run(routeBin, args...)
	if err != nil {
		if strings.Contains(out, "not in table") {
			return false, nil
		}
		return false, fmt.Errorf("deleting the exclusion route for %s: %w: %s", e.Host, err, strings.TrimSpace(out))
	}
	return true, nil
}
