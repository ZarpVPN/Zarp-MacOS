package route

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type scopedRecord struct {
	entry scopedEntry
	owned bool
}
type scopedWorld struct {
	records    map[string]scopedRecord
	failDelete bool
	failAdd    string
}

func (w *scopedWorld) run(_ string, args []string) (string, error) {
	if len(args) < 7 || args[3] != "-ifscope" || args[5] != "-net" {
		return "", errors.New("unexpected fake scoped command")
	}
	key := args[4] + "/" + args[6]
	switch args[1] {
	case "get":
		record, ok := w.records[key]
		if !ok {
			return "not in table", errors.New("absent")
		}
		prefix := netip.MustParsePrefix(record.entry.Prefix)
		mask := "128.0.0.0"
		if prefix.Addr().Is6() {
			mask = "8000::"
		}
		marker := ""
		if record.owned {
			marker = ",PROTO1"
		}
		return fmt.Sprintf("destination: %s\nmask: %s\ngateway: %s\ninterface: %s\nflags: <UP,GATEWAY,DONE,STATIC,IFSCOPE%s>\n", prefix.Addr(), mask, record.entry.Gateway, record.entry.Interface, marker), nil
	case "add":
		if args[6] == w.failAdd {
			return "File exists", errors.New("collision")
		}
		w.records[key] = scopedRecord{entry: scopedEntry{Prefix: args[6], Interface: args[4], Gateway: args[7]}, owned: true}
		return "", nil
	case "delete":
		if w.failDelete {
			return "failure", errors.New("remove")
		}
		delete(w.records, key)
		return "", nil
	}
	return "", errors.New("unsupported fake command")
}

func TestScopedDirectRoutesPreserveExistingAndReplacedEntries(t *testing.T) {
	base := scopedEntry{Prefix: "0.0.0.0/1", Gateway: "192.168.1.1", Interface: "en0"}
	w := &scopedWorld{records: map[string]scopedRecord{"en0/0.0.0.0/1": {entry: base}}}
	f := &fakeRunner{handler: w.run}
	router := New(f)
	journal := NewScopedJournal(filepath.Join(t.TempDir(), "scoped.json"))
	lease, err := router.AcquireScopedDirect([]*Physical{{Interface: "en0", Index: 1, Gateway: net.ParseIP("192.168.1.1")}, {Interface: "en0", Index: 1, Gateway: net.ParseIP("fe80::1"), GatewayZone: "en0"}}, journal)
	if err != nil || lease.Verify() != nil {
		t.Fatal("scoped acquisition failed", err)
	}
	replacement := w.records["en0/128.0.0.0/1"]
	replacement.entry.Gateway = "192.168.1.2"
	w.records["en0/128.0.0.0/1"] = replacement
	if lease.Verify() == nil {
		t.Fatal("external replacement was ignored")
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if len(w.records) != 2 || w.records["en0/0.0.0.0/1"].owned || w.records["en0/128.0.0.0/1"].entry.Gateway != "192.168.1.2" {
		t.Fatal("pre-existing or external routes were removed")
	}
	for _, call := range f.log() {
		if strings.Contains(call, "default") || !strings.Contains(call, "-ifscope en0") {
			t.Fatal("a global route was selected")
		}
	}
}

func TestScopedRecoveryRetainsFailuresAndRejectsUnsafeJournalBeforeCommands(t *testing.T) {
	w := &scopedWorld{records: map[string]scopedRecord{}}
	f := &fakeRunner{handler: w.run}
	router := New(f)
	path := filepath.Join(t.TempDir(), "scoped.json")
	journal := NewScopedJournal(path)
	lease, err := router.AcquireScopedDirect([]*Physical{{Interface: "en0", Index: 1, Gateway: net.ParseIP("192.168.1.1")}}, journal)
	if err != nil {
		t.Fatal(err)
	}
	w.failDelete = true
	if lease.Close() == nil {
		t.Fatal("cleanup failure was hidden")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("recovery record was lost")
	}
	w.failDelete = false
	if len(journal.Recover(router)) != 0 || len(w.records) != 0 {
		t.Fatal("owned recovery did not finish")
	}
	for _, data := range []string{`[{"prefix":"0.0.0.0/0","gateway":"192.168.1.1","interface":"en0"}]`, `[{"prefix":"0.0.0.0/1","gateway":"192.168.1.1","interface":"en0","unknown":true}]`, `null`} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		before := len(f.log())
		if len(journal.Recover(router)) == 0 || len(f.log()) != before {
			t.Fatal("invalid journal reached route commands")
		}
	}
}

func TestScopedPartialSetupRollsBackOwnedEntriesWithoutDeletingCollision(t *testing.T) {
	w := &scopedWorld{records: map[string]scopedRecord{}, failAdd: "128.0.0.0/1"}
	f := &fakeRunner{handler: w.run}
	router := New(f)
	journal := NewScopedJournal(filepath.Join(t.TempDir(), "scoped.json"))
	if _, err := router.AcquireScopedDirect([]*Physical{{Interface: "en0", Index: 1, Gateway: net.ParseIP("192.168.1.1")}}, journal); err == nil {
		t.Fatal("collision accepted")
	}
	if len(w.records) != 0 {
		t.Fatal("partial setup was not rolled back")
	}
	for _, call := range f.log() {
		if strings.Contains(call, " delete ") && strings.Contains(call, "128.0.0.0/1") {
			t.Fatal("collision was deleted")
		}
	}
}

func TestCustomNumericDNSRestoresExactPriorService(t *testing.T) {
	world := newDNSWorld()
	world.servers["Wi-Fi"] = []string{"192.168.1.9"}
	dns := NewDNSOverride(&fakeRunner{handler: world.fail}, filepath.Join(t.TempDir(), "dns.json"))
	if err := dns.ApplyServers("en0", []string{"9.9.9.9"}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(world.servers["Wi-Fi"], ",") != "9.9.9.9" {
		t.Fatal("custom resolver not applied")
	}
	if err := dns.Restore(); err != nil || strings.Join(world.servers["Wi-Fi"], ",") != "192.168.1.9" {
		t.Fatal("prior resolver not restored", err)
	}
	before := world.setCalls
	if dns.ApplyServers("en0", []string{"resolver.example; command"}) == nil || world.setCalls != before {
		t.Fatal("unvalidated DNS reached networksetup")
	}
}
