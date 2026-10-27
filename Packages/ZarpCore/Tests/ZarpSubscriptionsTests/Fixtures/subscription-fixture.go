// This fixture is never production code. It serves fixed synthetic subscription
// responses only on numeric loopback, has a 40-second cap and stops on pipe EOF.
// It owns no system tunnel, routes, DNS, keychain or outbound connection.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 1 {
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	go func() { _, _ = io.Copy(io.Discard, os.Stdin); cancel() }()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		os.Exit(2)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Zarp isolated fixture CA"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, MaxPathLen: 0, MaxPathLenZero: true}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		os.Exit(2)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		os.Exit(2)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: root.NotBefore, NotAfter: root.NotAfter, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, rootKey)
	if err != nil {
		os.Exit(2)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		os.Exit(2)
	}
	defer listener.Close()
	good := []byte("trojan://private-fixture-password@server.example.test:443#Fixture\n")
	gzipBody := func(body []byte) []byte {
		var data bytes.Buffer
		writer := gzip.NewWriter(&data)
		_, _ = writer.Write(body)
		_ = writer.Close()
		return data.Bytes()
	}
	compressed := gzipBody(good)
	large := gzipBody(append(good, bytes.Repeat([]byte(" "), 2*1024*1024)...))
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			w.WriteHeader(403)
			return
		}
		switch r.URL.Path {
		case "/gzip", "/gzip-large":
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Set-Cookie", "fixture=must-not-persist; Secure")
			body := compressed
			if r.URL.Path == "/gzip-large" {
				body = large
			}
			_, _ = w.Write(body)
		case "/redirect":
			w.Header().Set("Location", "/gzip")
			w.WriteHeader(302)
		case "/downgrade":
			w.Header().Set("Location", "http://127.0.0.1:1/do-not-follow")
			w.WriteHeader(302)
		case "/agents":
			if r.UserAgent() == "Zarp/1.0" {
				_, _ = io.WriteString(w, "<html>fixture</html>")
			} else {
				_, _ = w.Write(good)
			}
		case "/slow":
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		default:
			w.WriteHeader(404)
		}
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 2 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: time.Second,
		ErrorLog: log.New(io.Discard, "", 0), BaseContext: func(net.Listener) context.Context { return ctx },
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: key}}}}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.ServeTLS(listener, "", "") }()
	metadata := map[string]any{"version": 1, "endpoint": "https://" + listener.Addr().String(), "certificate": base64.StdEncoding.EncodeToString(rootDER)}
	if json.NewEncoder(os.Stdout).Encode(metadata) != nil {
		cancel()
	}
	<-ctx.Done()
	_ = server.Close()
	<-done
}
