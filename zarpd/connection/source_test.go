package connection

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSharedSwiftGoSourceVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "connection-contracts.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct{ Sources []vector }
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, v := range fixture.Sources {
		t.Run(v.Name, func(t *testing.T) {
			source, err := DecodeSource([]byte(v.JSON))
			if v.ErrorField != "" {
				if err != (Error{v.ErrorField}) {
					t.Fatalf("expected %s, got %v", v.ErrorField, err)
				}
				if strings.Contains(err.Error(), "private-source-token") {
					t.Fatal("source error exposed token")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if source.ID() != v.ID {
				t.Fatal("Swift/Go source identity differs")
			}
			raw, err := json.Marshal(source)
			if err != nil {
				t.Fatal(err)
			}
			copy, err := DecodeSource(raw)
			if err != nil || copy.ID() != source.ID() {
				t.Fatal("source round trip lost identity")
			}
			if strings.Contains(fmt.Sprintf("%v %#v", source, source), "private-source-token") {
				t.Fatal("source display exposed token")
			}
		})
	}
}

func TestSourceModesAndUrlBoundaries(t *testing.T) {
	if (Source{Kind: WarpSource}).Mode() != Warp || (Source{Kind: ManualSource}).Mode() != Server || (Source{Kind: SubscriptionSource}).Mode() != Server {
		t.Fatal("source mixed WARP and server account requirements")
	}
	for _, data := range [][]byte{[]byte(strings.Repeat("A", MaxSourceBytes+1)), []byte("private-source-token"), []byte(`{"kind":"subscription","subscriptionURL":"\ud800"}`)} {
		if _, err := DecodeSource(data); err == nil || strings.Contains(err.Error(), "private-source-token") {
			t.Fatal("malformed source accepted or leaked token")
		}
	}
}
