package route

// Route/DNS state exists only in the fake worlds. No system runner is used.
import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestExclusionUndoRetainsItsRecordUntilOwnedCleanupSucceeds(t *testing.T) {
	w := newWorld()
	r, _ := w.router()
	path := journalPath(t)
	undo, err := r.AddExclusion(testEndpoint, testPhys, NewJournal(path))
	if err != nil {
		t.Fatal(err)
	}
	w.fail = func(_ string, args []string) (string, error) {
		if len(args) > 1 && args[1] == "delete" {
			return "fake denied", errors.New("fake error")
		}
		return "", nil
	}
	if err := undo(); err == nil || !exists(path) || len(w.routes) != 1 {
		t.Fatal("failed undo erased its recovery record")
	}
	w.fail = nil
	if err := undo(); err != nil || exists(path) || len(w.routes) != 0 {
		t.Fatalf("fake retry failed: %v", err)
	}
}

func TestJournalRecoveryKeepsOnlyFailuresAndRejectsInvalidRecordsWithoutCommands(t *testing.T) {
	w := newWorld()
	r, _ := w.router()
	path := journalPath(t)
	j := NewJournal(path)
	for _, value := range []string{"162.159.198.2", "162.159.198.3"} {
		w.routes["inet "+value], w.gateways["inet "+value] = "en0", "192.168.34.1"
		if err := j.add(journalEntry{Host: value, Interface: "en0", Gateway: "192.168.34.1"}); err != nil {
			t.Fatal(err)
		}
	}
	w.fail = func(_ string, args []string) (string, error) {
		if len(args) > 1 && args[1] == "delete" && strings.Contains(strings.Join(args, " "), "162.159.198.3") {
			return "fake denied", errors.New("fake error")
		}
		return "", nil
	}
	if errs := j.Recover(r); len(errs) != 1 {
		t.Fatalf("expected exactly one failed record: %v", errs)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var records []journalEntry
	if json.Unmarshal(data, &records) != nil || len(records) != 1 || records[0].Host != "162.159.198.3" {
		t.Fatal("partial recovery lost failures or retained successes")
	}
	for _, data := range []string{`null`, `[{"host":"default","interface":"en0"}]`, `[{"host":"162.159.198.2","interface":"en0","gateway":"private-invalid"}]`} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		_, commands := newWorld().router()
		fakeRouter := New(commands)
		if errs := j.Recover(fakeRouter); len(errs) == 0 || len(commands.log()) != 0 {
			t.Fatal("invalid recovery data became system commands")
		}
		if after, _ := os.ReadFile(path); string(after) != data {
			t.Fatal("invalid recovery evidence changed")
		}
	}
}

func TestFailedRouteRollbackIsFatalAndPreservesUnrelatedRoutes(t *testing.T) {
	for _, family := range []string{"ipv4", "ipv6"} {
		t.Run(family, func(t *testing.T) {
			w := newWorld()
			first, second, key := "0.0.0.0/1", "128.0.0.0/1", "inet 0.0.0.0/1"
			if family == "ipv6" {
				first, second, key = "::/1", "8000::/1", "inet6 ::/1"
			}
			w.routes["inet 203.0.113.0/24"] = "utun29"
			prefix := "inet "
			if family == "ipv6" {
				prefix = "inet6 "
			}
			w.failAdd[prefix+second] = errors.New("fake setup failure")
			w.fail = func(name string, args []string) (string, error) {
				joined := " " + strings.Join(args, " ") + " "
				if name == routeBin && strings.Contains(joined, " delete ") && strings.Contains(joined, " "+first+" ") {
					return "fake rollback denied", errors.New("fake deletion failure")
				}
				return "", nil
			}
			r, _ := w.router()
			ft, _, err := r.EnableFullTunnel(FullTunnelConfig{Utun: "utun5", IPv6Addr: "2606:4700:110::1", Exclude: testEndpoint, Physical: testPhys}, nil)
			if ft != nil || !errors.Is(err, ErrCleanupIncomplete) {
				t.Fatalf("rollback uncertainty lost: ft=%v err=%v", ft, err)
			}
			want := map[string]string{key: "utun5", "inet 203.0.113.0/24": "utun29"}
			if !reflect.DeepEqual(w.routes, want) {
				t.Fatalf("remaining cleanup was skipped or foreign state changed: %v", w.routes)
			}
		})
	}
}

func TestDNSCommandFailureWithSuccessfulRollbackRemovesOnlyItsBackup(t *testing.T) {
	w := newDNSWorld()
	w.servers["Wi-Fi"] = []string{"10.0.0.53"}
	path := filepath.Join(t.TempDir(), "dns.json")
	d := NewDNSOverride(&fakeRunner{handler: func(name string, args []string) (string, error) {
		if name == networksetup && len(args) > 2 && args[0] == "-setdnsservers" && args[2] == CloudflareDNSv4[0] {
			w.servers["Wi-Fi"] = append([]string(nil), CloudflareDNSv4...)
			return "fake command failed after changing state", errors.New("fake error")
		}
		return w.fail(name, args)
	}}, path)
	if err := d.Apply("en0", false); err == nil || errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("confirmed rollback misclassified: %v", err)
	}
	if exists(path) || !reflect.DeepEqual(w.servers["Wi-Fi"], []string{"10.0.0.53"}) {
		t.Fatal("confirmed rollback did not restore its original state")
	}
}

func TestUncertainDNSApplyCannotBecomeAWarningOnAWorkingTunnel(t *testing.T) {
	w, dnsState := newWorld(), newDNSWorld()
	dnsState.servers["Wi-Fi"] = []string{"10.0.0.53"}
	dnsState.failSet = true
	path := filepath.Join(t.TempDir(), "dns.json")
	d := NewDNSOverride(&fakeRunner{handler: dnsState.fail}, path)
	r := New(&fakeRunner{handler: func(name string, args []string) (string, error) {
		if name == routeBin {
			return w.run(name, args)
		}
		return dnsState.fail(name, args)
	}})
	ft, _, err := r.EnableFullTunnel(FullTunnelConfig{Utun: "utun5", OverrideDNS: true, Exclude: testEndpoint, Physical: testPhys}, d)
	if ft != nil || !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("uncertain DNS became a successful tunnel: %v", err)
	}
	if len(w.routes) != 0 || !exists(path) {
		t.Fatal("owned routes were not cleaned or DNS recovery evidence was lost")
	}
	dnsState.failSet = false
	if err := d.RecoverStale(); err != nil || exists(path) {
		t.Fatalf("retained original DNS could not be recovered by the fake runner: %v", err)
	}
}
