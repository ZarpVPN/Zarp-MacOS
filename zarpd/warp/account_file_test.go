package warp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestAccountFileRejectsNonregularSymlinkOversizeAndUnsafeMode(t *testing.T) {
	root := t.TempDir()
	valid := filepath.Join(root, "valid.json")
	if err := os.WriteFile(valid, []byte(`{"private_key":"private-account-key","endpoint_pub_key":"private-peer-key"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if cfg, err := LoadConfig(valid); err != nil || cfg.PrivateKey != "private-account-key" {
		t.Fatal("regular account refused", err)
	}
	fifo := filepath.Join(root, "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(valid, link); err != nil {
		t.Fatal(err)
	}
	fifoLink := filepath.Join(root, "fifo-link")
	if err := os.Symlink(fifo, fifoLink); err != nil {
		t.Fatal(err)
	}
	oversize := filepath.Join(root, "oversize.json")
	if err := os.WriteFile(oversize, []byte(strings.Repeat(" ", maxAccountConfigBytes+1)), 0600); err != nil {
		t.Fatal(err)
	}
	unsafe := filepath.Join(root, "unsafe.json")
	if err := os.WriteFile(unsafe, []byte(`{"private_key":"x","endpoint_pub_key":"y"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0666); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{root, fifo, link, fifoLink, oversize, unsafe} {
		result := make(chan error, 1)
		go func() { _, err := LoadConfig(path); result <- err }()
		select {
		case err := <-result:
			if err == nil {
				t.Fatal("unsafe account source accepted")
			}
		case <-time.After(time.Second):
			// Release a regression's FIFO open/read, then join it before failing.
			if path == fifo || path == fifoLink {
				fd, err := unix.Open(fifo, unix.O_RDWR|unix.O_NONBLOCK, 0)
				if err == nil {
					_ = unix.Close(fd)
				}
			}
			select {
			case <-result:
			case <-time.After(time.Second):
				t.Fatal("account reader could not be joined")
			}
			t.Fatal("account metadata read blocked")
		}
	}
}

func TestAccountFileBoundsAndErrorsDoNotExposePathOrData(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "private-path-secret.json")
	for _, data := range []string{"", `{"private_key":"private-account-secret"}`, `{"private_key":private-account-secret}`, strings.Repeat("x", maxAccountConfigBytes+1)} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		cfg, err := LoadConfig(path)
		if err == nil || cfg != nil || strings.Contains(err.Error(), "private-") {
			t.Fatal("invalid account exposed private input or succeeded")
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); !os.IsNotExist(err) || strings.Contains(err.Error(), "private-") {
		t.Fatal("missing-file identity lost or private path exposed")
	}
}
