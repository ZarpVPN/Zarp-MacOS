package route

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/feg55/zarp-macos/zarpd/connection"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Scoped physical /1 routes are visible to IP_BOUND_IF sockets only. Global
// host exclusions would bypass the tunnel for every app sharing that destination.
type scopedEntry struct {
	Prefix    string `json:"prefix"`
	Gateway   string `json:"gateway"`
	Interface string `json:"interface"`
}

type ScopedJournal struct {
	path string
	mu   sync.Mutex
}

func NewScopedJournal(path string) *ScopedJournal { return &ScopedJournal{path: path} }

func (e scopedEntry) valid() bool {
	prefix, err := netip.ParsePrefix(e.Prefix)
	if err != nil || prefix.Bits() != 1 || prefix != prefix.Masked() || !(e.Prefix == "0.0.0.0/1" || e.Prefix == "128.0.0.0/1" || e.Prefix == "::/1" || e.Prefix == "8000::/1") {
		return false
	}
	if len(e.Interface) < 2 || len(e.Interface) > 15 || strings.HasPrefix(e.Interface, "utun") || !(e.Interface[0] >= 'a' && e.Interface[0] <= 'z' || e.Interface[0] >= 'A' && e.Interface[0] <= 'Z') {
		return false
	}
	for _, c := range []byte(e.Interface) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	gw, err := netip.ParseAddr(e.Gateway)
	return err == nil && gw.Is4() == prefix.Addr().Is4() && !gw.IsUnspecified() && !gw.IsMulticast() && !gw.IsLoopback() && (gw.Zone() == "" || gw.Zone() == e.Interface)
}

func (j *ScopedJournal) read() ([]scopedEntry, error) {
	data, err := os.ReadFile(j.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var values []scopedEntry
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if connection.ValidateDocumentJSON(data, 65536) != nil || decoder.Decode(&values) != nil || values == nil || len(values) > 4 {
		return nil, errors.New("invalid scoped route recovery data retained")
	}
	seen := map[scopedEntry]bool{}
	for _, value := range values {
		if !value.valid() || seen[value] {
			return nil, errors.New("invalid scoped route recovery data retained")
		}
		seen[value] = true
	}
	return values, nil
}

func (j *ScopedJournal) write(entries []scopedEntry) error {
	if len(entries) == 0 {
		if err := os.Remove(j.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(j.path), 0700); err != nil {
		return err
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(j.path), ".scoped-routes-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), j.path)
}

func scopedArgs(operation string, entry scopedEntry) []string {
	family := "-inet"
	if strings.Contains(entry.Prefix, ":") {
		family = "-inet6"
	}
	args := []string{"-n", operation, family, "-ifscope", entry.Interface, "-net", entry.Prefix}
	if operation == "add" {
		args = append(args, entry.Gateway, "-proto1")
	}
	return args
}

func scopedMatches(output string, e scopedEntry, owned bool) bool {
	fields := parseRouteGet(output)
	if fields["interface"] != e.Interface || fields["gateway"] != e.Gateway {
		return false
	}
	prefix := netip.MustParsePrefix(e.Prefix)
	destination := fields["destination"]
	if destination == "default" {
		if !prefix.Addr().IsUnspecified() {
			return false
		}
		destination = prefix.Addr().String()
	}
	if destination != prefix.Addr().String() {
		return false
	}
	mask, err := netip.ParseAddr(fields["mask"])
	if err != nil || mask.Is4() != prefix.Addr().Is4() {
		return false
	}
	if prefix.Addr().Is4() && mask != netip.MustParseAddr("128.0.0.0") || prefix.Addr().Is6() && mask != netip.MustParseAddr("8000::") {
		return false
	}
	flags := map[string]bool{}
	for _, flag := range strings.Split(strings.Trim(fields["flags"], "<>"), ",") {
		if flag == "" || flags[flag] {
			return false
		}
		switch flag {
		case "UP", "GATEWAY", "DONE", "STATIC", "IFSCOPE", "PROTO1", "PRCLONING", "CLONING", "GLOBAL":
		default:
			return false
		}
		flags[flag] = true
	}
	return flags["UP"] && flags["GATEWAY"] && flags["STATIC"] && flags["IFSCOPE"] && (!owned || flags["PROTO1"])
}

func (r *Router) removeScoped(entry scopedEntry) error {
	if !entry.valid() {
		return errors.New("invalid scoped route identity")
	}
	out, err := r.run.Run(routeBin, scopedArgs("get", entry)...)
	if err != nil {
		if strings.Contains(out, "not in table") {
			return nil
		}
		return errors.New("scoped route ownership check failed")
	}
	if !scopedMatches(out, entry, true) {
		return nil
	}
	out, err = r.run.Run(routeBin, scopedArgs("delete", entry)...)
	if err != nil && !strings.Contains(out, "not in table") {
		return errors.New("scoped route removal failed")
	}
	return nil
}

func (j *ScopedJournal) Recover(router *Router) []error {
	j.mu.Lock()
	defer j.mu.Unlock()
	entries, err := j.read()
	if err != nil {
		return []error{err}
	}
	var kept []scopedEntry
	var failures []error
	for _, entry := range entries {
		if err := router.removeScoped(entry); err != nil {
			kept = append(kept, entry)
			failures = append(failures, err)
		}
	}
	if err := j.write(kept); err != nil {
		failures = append(failures, err)
	}
	return failures
}

type ScopedDirect struct {
	router          *Router
	journal         *ScopedJournal
	owned, required []scopedEntry
	mu              sync.Mutex
	closed          bool
	checkedAt       time.Time
}

// AcquireScopedDirect never replaces or deletes a pre-existing route. The
// marker and exact scope/prefix/gateway must still match before owned cleanup.
func (r *Router) AcquireScopedDirect(physical []*Physical, journal *ScopedJournal) (*ScopedDirect, error) {
	if journal == nil {
		return nil, errors.New("scoped route recovery is unavailable")
	}
	journal.mu.Lock()
	entries, err := journal.read()
	journal.mu.Unlock()
	if err != nil || len(entries) != 0 {
		return nil, errors.Join(ErrCleanupIncomplete, errors.New("pending scoped route recovery"))
	}
	session := &ScopedDirect{router: r, journal: journal}
	fail := func(cause error) (*ScopedDirect, error) {
		if cleanup := session.Close(); cleanup != nil {
			return nil, errors.Join(ErrCleanupIncomplete, cause, cleanup)
		}
		return nil, cause
	}
	for _, phys := range physical {
		if phys == nil {
			continue
		}
		if phys.IsTunnel() || phys.Gateway == nil || phys.Gateway.IsUnspecified() {
			return fail(errors.New("physical gateway for application routing is unavailable"))
		}
		prefixes := v4Halves
		gateway := phys.Gateway.String()
		if phys.Gateway.To4() == nil {
			prefixes = v6Halves
			if phys.GatewayZone != "" {
				gateway += "%" + phys.GatewayZone
			}
		}
		for _, prefix := range prefixes {
			entry := scopedEntry{Prefix: prefix, Gateway: gateway, Interface: phys.Interface}
			if !entry.valid() {
				return fail(errors.New("invalid physical scoped route"))
			}
			session.required = append(session.required, entry)
			current, queryErr := r.run.Run(routeBin, scopedArgs("get", entry)...)
			if queryErr == nil && scopedMatches(current, entry, false) {
				continue
			}
			if queryErr != nil && !strings.Contains(current, "not in table") {
				return fail(errors.New("physical scoped route check failed"))
			}
			journal.mu.Lock()
			pending := append(append([]scopedEntry(nil), session.owned...), entry)
			err = journal.write(pending)
			journal.mu.Unlock()
			if err != nil {
				return fail(err)
			}
			out, addErr := r.run.Run(routeBin, scopedArgs("add", entry)...)
			if addErr != nil && strings.Contains(out, "File exists") {
				journal.mu.Lock()
				err = journal.write(session.owned)
				journal.mu.Unlock()
				if err != nil {
					return fail(errors.Join(ErrCleanupIncomplete, err))
				}
				return fail(errors.New("physical scoped route already exists"))
			}
			session.owned = pending
			if addErr != nil {
				return fail(errors.New("physical scoped route installation failed"))
			}
			installed, checkErr := r.run.Run(routeBin, scopedArgs("get", entry)...)
			if checkErr != nil || !scopedMatches(installed, entry, true) {
				return fail(errors.New("physical scoped route identity changed"))
			}
		}
	}
	if len(session.required) == 0 {
		return fail(errors.New("no physical route for application routing"))
	}
	return session, nil
}

func (s *ScopedDirect) Verify() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.verifyLocked()
}

// Coalesce checks from concurrent new connections. The connection monitor uses
// Verify directly, and close immediately invalidates this short-lived cache.
func (s *ScopedDirect) CheckForDial() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed && time.Since(s.checkedAt) < 250*time.Millisecond {
		return nil
	}
	return s.verifyLocked()
}

func (s *ScopedDirect) verifyLocked() error {
	if s.closed {
		return errors.New("physical scoped route is closed")
	}
	for _, entry := range s.required {
		out, err := s.router.run.Run(routeBin, scopedArgs("get", entry)...)
		if err != nil || !scopedMatches(out, entry, false) {
			return errors.New("physical scoped route changed")
		}
	}
	s.checkedAt = time.Now()
	return nil
}

func (s *ScopedDirect) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.journal.mu.Lock()
	defer s.journal.mu.Unlock()
	var kept []scopedEntry
	var failures []error
	for _, entry := range s.owned {
		if err := s.router.removeScoped(entry); err != nil {
			kept = append(kept, entry)
			failures = append(failures, err)
		}
	}
	s.owned = kept
	if err := s.journal.write(kept); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}
