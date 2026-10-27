package route

import "testing"

func TestForeignTunnelRouteDetectionIncludesSplitAndHostRoutes(t *testing.T) {
	for _, tc := range []struct {
		route, owned string
		foreign      bool
	}{
		{"0/1 10.0.0.1 UGSc utun4", "", true},
		{"203.0.113.2 10.0.0.1 UGHS utun4", "", true},
		{"::/1 fd00::1 UGSc utun8", "utun4", true},
		{"0/1 10.0.0.1 UGSc utun4", "utun4", false},
		{"fe80::%utun4/64 fe80::1 UcI utun4", "", false},
		{"ff00::/8 fe80::1 UmCI utun4", "", false},
		{"default 192.0.2.1 UGSc en0", "", false},
	} {
		runner := &fakeRunner{handler: func(string, []string) (string, error) {
			return "Destination Gateway Flags Netif\n" + tc.route + "\n", nil
		}}
		foreign, err := New(runner).HasForeignTunnelRoutes(tc.owned)
		if err != nil || foreign != tc.foreign {
			t.Fatalf("route %q: foreign=%v error=%v", tc.route, foreign, err)
		}
		if len(runner.log()) != 1 || runner.log()[0] != "/usr/sbin/netstat -rn" {
			t.Fatal("route guard mutated the network")
		}
	}
	if _, err := New(&fakeRunner{}).HasForeignTunnelRoutes(""); err == nil {
		t.Fatal("missing route table accepted")
	}
}
