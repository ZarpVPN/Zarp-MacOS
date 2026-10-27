package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/feg55/zarp-macos/zarpd/ipc"
	"golang.org/x/sys/unix"
)

// Only the private fake manager/socket exist here. No installed service,
// production account, WARP registration, tunnel or system runner is invoked.
func TestAccountFIFOLeavesPrivatePingAndStatusResponsive(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "zarp-status-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	fifo := filepath.Join(dir, "account")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	m := NewManager(Config{Accounts: &FileAccounts{Path: fifo}, Opener: &fakeOpener{}, Measurer: &fakeMeasurer{}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	socket := filepath.Join(dir, "s")
	go func() { done <- ipc.Serve(ctx, socket, m.Handle, ipc.Options{SocketMode: 0600, SocketGID: -1}) }()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("private IPC server did not stop")
		}
	}()
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("private socket startup")
		}
		time.Sleep(time.Millisecond)
	}
	client, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	encoder := json.NewEncoder(client)
	decoder := json.NewDecoder(bufio.NewReader(client))
	for i, method := range []string{"ping", "status"} {
		if err := encoder.Encode(ipc.Request{ID: uint64(i + 1), Method: method}); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[uint64]bool{}
	for i := 0; i < 2; i++ {
		var r ipc.Response
		if err := decoder.Decode(&r); err != nil {
			t.Fatal("private status blocked by nonregular account", err)
		}
		if r.Error != nil || r.ID < 1 || r.ID > 2 || seen[r.ID] {
			t.Fatal("invalid private IPC response")
		}
		seen[r.ID] = true
		var fields map[string]any
		if json.Unmarshal(r.Result, &fields) != nil || fields["accountRegistered"] != false {
			t.Fatal("invalid account incorrectly registered")
		}
	}
}
