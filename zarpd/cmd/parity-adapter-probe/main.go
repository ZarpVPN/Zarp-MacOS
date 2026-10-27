// parity-adapter-probe is a private test helper. It never creates a TUN, modifies
// routes/DNS or talks to production IPC. The system-tun destination is user-run only.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const measurement = "198.18.0.2"

func fixture(directory string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "inner.example.test"}, DNSNames: []string{"inner.example.test"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	for name, data := range map[string][]byte{"cert.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}),
		"key.pem": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), "nonce": []byte(hex.EncodeToString(nonce))} {
		if err := os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
			return err
		}
	}
	return nil
}

func dnsQuery(nonce string) []byte {
	id := make([]byte, 2)
	_, _ = rand.Read(id)
	query := append(id, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0)
	for _, label := range []string{nonce[:24], "probe", "example", "test"} {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	return append(query, 0, 0, 1, 0, 1)
}

func dnsReply(query []byte) []byte {
	reply := append([]byte(nil), query...)
	reply[2], reply[3], reply[6], reply[7] = 0x81, 0x80, 0, 1
	return append(reply, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 192, 0, 2, 1)
}

func probe(directory, kind, network string, loopbackPort int, fromPipe bool) bool {
	var secret, certificate []byte
	var err error
	if fromPipe {
		info, statErr := os.Stdin.Stat()
		if statErr != nil || info.Mode()&os.ModeNamedPipe == 0 {
			return false
		}
		var fixture struct {
			Nonce       string `json:"nonce"`
			Certificate string `json:"certificate"`
		}
		decoder := json.NewDecoder(io.LimitReader(os.Stdin, 16385))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&fixture) != nil {
			return false
		}
		var trailing any
		if decoder.Decode(&trailing) != io.EOF || len(fixture.Certificate) > 8192 {
			return false
		}
		secret, certificate = []byte(fixture.Nonce), []byte(fixture.Certificate)
	} else {
		secret, err = os.ReadFile(filepath.Join(directory, "nonce"))
		if kind == "https" {
			certificate, err = os.ReadFile(filepath.Join(directory, "cert.pem"))
		}
	}
	if err != nil || len(secret) != 64 {
		return false
	}
	if raw, err := hex.DecodeString(string(secret)); err != nil || len(raw) != 32 {
		return false
	}
	host, port := "127.0.0.1", loopbackPort
	if network == "system-tun" {
		if !fromPipe || loopbackPort != 0 {
			return false
		}
		host = measurement
		port = map[string]int{"https": 443, "udp": 9999, "dns": 53}[kind]
	} else if network != "loopback" {
		return false
	}
	if port < 1 || port > 65535 {
		return false
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	if kind == "https" {
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(certificate) {
			return false
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		transport := &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "inner.example.test"},
			DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext}
		defer transport.CloseIdleConnections()
		request, err := http.NewRequestWithContext(ctx, "GET", "https://"+address+"/probe", nil)
		if err != nil {
			return false
		}
		request.Header.Set("X-Zarp-Probe", string(secret))
		response, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Do(request)
		if err != nil {
			return false
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 128))
		return err == nil && response.StatusCode == 200 && string(body) == "private-adapter-https"
	}
	if kind != "udp" && kind != "dns" {
		return false
	}
	conn, err := net.DialTimeout("udp4", address, time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	message := append([]byte("private-adapter-udp-"), secret...)
	expected := message
	if kind == "dns" {
		message = dnsQuery(string(secret))
		expected = dnsReply(message)
	}
	if _, err := conn.Write(message); err != nil {
		return false
	}
	buffer := make([]byte, 512)
	n, err := conn.Read(buffer)
	return err == nil && bytes.Equal(buffer[:n], expected)
}

func main() {
	directory := flag.String("fixture", "", "private test fixture directory")
	generate := flag.Bool("generate", false, "generate private TLS/nonce files only; no network access")
	kind := flag.String("probe", "", "https, udp or dns")
	network := flag.String("network", "loopback", "loopback, or user-run system-tun")
	port := flag.Int("loopback-port", 0, "owned loopback server port")
	fromPipe := flag.Bool("fixture-stdin", false, "read a bounded private fixture from an inherited pipe")
	flag.Parse()
	if *directory == "" || flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	ok := false
	if *generate {
		ok = *kind == "" && fixture(*directory) == nil
	} else {
		ok = probe(*directory, *kind, *network, *port, *fromPipe)
	}
	caseName := *kind
	if caseName != "https" && caseName != "udp" && caseName != "dns" {
		caseName = "invalid"
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"version": 1, "ok": ok, "case": caseName, "fixture_only": *generate, "uid": os.Getuid()})
	if !ok {
		os.Exit(1)
	}
}
