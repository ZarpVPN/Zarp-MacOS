// parity-packet-probe has only fixed numeric-loopback fixtures. --capture is a
// user-run, passive BPF check. No TUN, routes, DNS, physical binding or production
// IPC/configuration/account exists in this program. It spawns no child process.
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
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/feg55/zarp-macos/zarpd/relay"
	"golang.org/x/net/proxy"
)

type report struct {
	HopLimits         [][]int `json:"udp_packet_hop_limits,omitempty"`
	HopLimitRequested bool    `json:"udp_fake_hop_limit_requested,omitempty"`
	HopLimitVerified  bool    `json:"udp_fake_hop_limit_verified,omitempty"`
	Family            string  `json:"ip_family,omitempty"`
	Version           int     `json:"version"`
	Scenario          string  `json:"scenario"`
	Phase             string  `json:"phase"`
	Status            string  `json:"status"`
	Cleanup           string  `json:"cleanup"`
	Reason            string  `json:"reason_code,omitempty"`
	Duration          float64 `json:"duration_seconds"`
	SystemChanged     bool    `json:"system_network_changed"`
	CaptureStarted    bool    `json:"capture_started"`
	CaptureError      string  `json:"capture_error,omitempty"`
	BPFOpenErrno      int     `json:"bpf_open_errno,omitempty"`
	HTTPSFlows        int     `json:"https_flows"`
	UDPAssociations   int     `json:"udp_associations"`
	Captured          int     `json:"captured_packets"`
	Drops             int     `json:"capture_drops"`
	TCPLengths        [][]int `json:"tcp_packet_payload_lengths,omitempty"`
	TCPSplit          bool    `json:"tcp_packet_split_verified"`
	UDPOrder          bool    `json:"udp_fake_order_tuple_verified"`
}

func main() {
	if len(os.Args) < 2 || len(os.Args) > 4 {
		os.Exit(2)
	}
	capture := os.Args[1] == "--capture"
	if !capture && os.Args[1] != "--loopback-check" {
		os.Exit(2)
	}
	started := time.Now()
	result := report{Version: 1, Scenario: "outer-packet-loopback", Phase: "loopback", Status: "FAIL", Cleanup: "PASS"}
	for _, arg := range os.Args[2:] {
		switch {
		case arg == "--ipv6" && result.Family == "":
			result.Family = "ipv6"
		case arg == "--fake-hop-limit" && !result.HopLimitRequested:
			result.HopLimitRequested = true
		default:
			os.Exit(2)
		}
	}
	if capture {
		result.Phase = "capture"
	}
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" || capture && os.Geteuid() != 0 {
		result.Status = "SKIP"
		result.Reason = "capture_requires_macos_arm64_root"
	} else {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		// The user-run supervisor owns an exclusive stdin pipe. Loss of that
		// parent cancels the same resources, without signaling any other PID.
		go func() { _, _ = io.Copy(io.Discard, os.Stdin); cancel() }()
		err := run(ctx, capture, &result)
		cancel()
		stop()
		if err == nil {
			result.Status = "PASS"
		} else if result.Reason == "" {
			result.Reason = "private_loopback_check_failed"
		}
	}
	result.Duration = time.Since(started).Seconds()
	data, _ := json.Marshal(result)
	os.Stdout.Write(append(append([]byte("RESULT "), data...), '\n'))
	if result.Status == "FAIL" {
		os.Exit(1)
	}
}

func run(ctx context.Context, capture bool, result *report) (returned error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "outer.example.test"}, DNSNames: []string{"outer.example.test"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	ipv6 := result.Family == "ipv6"
	tcpNetwork, tcpAddress, udpNetwork, udpIP := "tcp4", "127.0.0.1:0", "udp4", net.IPv4(127, 0, 0, 1)
	if ipv6 {
		tcpNetwork, tcpAddress, udpNetwork, udpIP = "tcp6", "[::1]:0", "udp6", net.IPv6loopback
	}
	listener, err := net.Listen(tcpNetwork, tcpAddress)
	if err != nil {
		return err
	}
	defer listener.Close()
	tcpTarget := listener.Addr().(*net.TCPAddr).AddrPort()
	udpServer, err := net.ListenUDP(udpNetwork, &net.UDPAddr{IP: udpIP})
	if err != nil {
		return err
	}
	defer udpServer.Close()
	udpTarget := udpServer.LocalAddr().(*net.UDPAddr).AddrPort()
	var mutex sync.Mutex
	var ports []uint16
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	tlsConfig.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if hello.ServerName != "outer.example.test" || len(hello.SupportedProtos) != 1 || hello.SupportedProtos[0] != "http/1.1" {
			return nil, errors.New("wrong private SNI or ALPN")
		}
		address, err := netip.ParseAddrPort(hello.Conn.RemoteAddr().String())
		if err != nil || !address.Addr().IsLoopback() {
			return nil, errors.New("not private peer")
		}
		mutex.Lock()
		ports = append(ports, address.Port())
		mutex.Unlock()
		return nil, nil
	}
	server := &http.Server{TLSConfig: tlsConfig, ReadHeaderTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: time.Second,
		ErrorLog: log.New(io.Discard, "", 0), BaseContext: func(net.Listener) context.Context { return ctx },
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "private-real-https-marker") })}
	serverDone := make(chan struct{})
	go func() { defer close(serverDone); _ = server.ServeTLS(listener, "", "") }()
	defer func() { _ = server.Close(); <-serverDone }()
	stopListeners := context.AfterFunc(ctx, func() { _ = listener.Close(); _ = udpServer.Close() })
	defer stopListeners()
	var wire *wireCapture
	if capture {
		wire, err = openWireCapture(ctx, tcpTarget.Port(), udpTarget.Port(), ipv6)
		if err != nil {
			result.Status = "SKIP"
			result.Reason = "passive_bpf_unavailable"
			var number syscall.Errno
			if errors.As(err, &number) {
				result.BPFOpenErrno = int(number)
			}
			return err
		}
		result.CaptureStarted = true
		defer func() {
			if !wire.stop() {
				result.Cleanup = "FAIL"
				returned = errors.New("capture cleanup failed")
			}
			result.Captured = len(wire.packets)
			if wire.drops >= 0 {
				result.Drops = wire.drops
			}
			result.CaptureError = wire.errorCode()
		}()
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	secret := hex.EncodeToString(nonce[:])
	var expected []tcpExpectation
	tcpRelay, err := relay.StartTCP(ctx, relay.TCPConfig{Target: tcpTarget, ServerName: "outer.example.test", Username: "fixture", Password: secret, Lifetime: 20 * time.Second,
		Observe: func(hello relay.Hello, chunks []int) {
			mutex.Lock()
			expected = append(expected, tcpExpectation{chunks: append([]int(nil), chunks...), wire: append([]byte(nil), hello.Wire...)})
			mutex.Unlock()
		}})
	if err != nil {
		return err
	}
	defer tcpRelay.Close()
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	for flow := 0; flow < 2; flow++ {
		dialer, err := proxy.SOCKS5("tcp", tcpRelay.Address(), &proxy.Auth{User: "fixture", Password: secret}, &net.Dialer{Timeout: 3 * time.Second})
		if err != nil {
			return err
		}
		transport := &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "outer.example.test", NextProtos: []string{"http/1.1"}},
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return dialer.(proxy.ContextDialer).DialContext(ctx, network, address)
			}}
		request, _ := http.NewRequestWithContext(ctx, "GET", "https://"+tcpTarget.String(), nil)
		response, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Do(request)
		if err != nil {
			transport.CloseIdleConnections()
			return err
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 256))
		response.Body.Close()
		transport.CloseIdleConnections()
		if readErr != nil || string(body) != "private-real-https-marker" || response.TLS == nil || !response.TLS.HandshakeComplete || response.TLS.NegotiatedProtocol != "http/1.1" {
			return errors.New("missing private HTTPS")
		}
		result.HTTPSFlows++
	}
	fake := []byte("invalid-loopback-quic-fake")
	real := []byte("private-real-udp-marker")
	fakeLimit := 0
	if result.HopLimitRequested {
		fakeLimit = 1
	}
	udpRelay, err := relay.StartUDP(ctx, relay.UDPConfig{FakeHopLimit: fakeLimit, Target: udpTarget, Username: "fixture", Password: secret, Lifetime: 20 * time.Second, Fake: fake})
	if err != nil {
		return err
	}
	defer udpRelay.Close()
	var udpSources []uint16
	for association := 0; association < 2; association++ {
		control, socket, err := udpAssociation(udpRelay.Address(), secret)
		if err != nil {
			return err
		}
		err = func() error {
			defer control.Close()
			defer socket.Close()
			packet := []byte{0, 0, 0, 1, 127, 0, 0, 1, 0, 0}
			if ipv6 {
				packet = make([]byte, 22)
				packet[3] = 4
				copy(packet[4:20], net.IPv6loopback)
			}
			binary.BigEndian.PutUint16(packet[len(packet)-2:], udpTarget.Port())
			packet = append(packet, real...)
			if _, err := socket.Write(packet); err != nil {
				return err
			}
			_ = udpServer.SetReadDeadline(time.Now().Add(3 * time.Second))
			buffer := make([]byte, 2048)
			n, first, err := udpServer.ReadFromUDPAddrPort(buffer)
			if err != nil || string(buffer[:n]) != string(fake) {
				return errors.New("missing fake")
			}
			n, second, err := udpServer.ReadFromUDPAddrPort(buffer)
			if err != nil || string(buffer[:n]) != string(real) || first != second {
				return errors.New("missing same-tuple real UDP")
			}
			udpSources = append(udpSources, first.Port())
			if _, err := udpServer.WriteToUDPAddrPort(real, second); err != nil {
				return err
			}
			n, err = socket.Read(buffer)
			if err != nil || n != len(packet) || !bytes.Equal(buffer[:n], packet) {
				return errors.New("missing reverse UDP")
			}
			return nil
		}()
		if err != nil {
			return err
		}
		result.UDPAssociations++
	}
	tcpRelay.Close()
	udpRelay.Close()
	mutex.Lock()
	defer mutex.Unlock()
	if len(expected) != 2 || len(ports) != 2 {
		return errors.New("missing fresh outer observations")
	}
	if ports[0] == ports[1] || udpSources[0] == udpSources[1] {
		return errors.New("outer tuples reused")
	}
	for i := range expected {
		expected[i].port = ports[i]
		if len(expected[i].chunks) != 3 || expected[i].chunks[0] != 1 {
			return errors.New("wrong stream chunks")
		}
	}
	if wire != nil {
		// Let the final loopback view arrive before joining the bounded reader.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
		if !wire.stop() {
			return errors.New("capture is incomplete")
		}
		if wire.errorCode() != "" {
			result.Reason = "passive_capture_incomplete"
			return errors.New("capture is incomplete")
		}
		result.TCPSplit = true
		result.UDPOrder = true
		for _, flow := range expected {
			lengths, ok := verifyTCPPackets(wire.packets, tcpTarget.Port(), flow)
			result.TCPLengths = append(result.TCPLengths, lengths)
			result.TCPSplit = result.TCPSplit && ok
		}
		result.HopLimitVerified = result.HopLimitRequested
		for _, source := range udpSources {
			if result.HopLimitRequested {
				result.HopLimits = append(result.HopLimits, udpPacketHopLimits(wire.packets, udpTarget.Port(), source))
				result.HopLimitVerified = result.HopLimitVerified && verifyUDPHopLimitPackets(wire.packets, udpTarget.Port(), source, fake, real)
			}
			result.UDPOrder = result.UDPOrder && verifyUDPPackets(wire.packets, udpTarget.Port(), source, fake, real)
		}
		if !result.TCPSplit {
			result.Reason = "tcp_packets_do_not_prove_split"
			return errors.New("split unverified")
		}
		if result.HopLimitRequested && !result.HopLimitVerified {
			result.Reason = "udp_packets_do_not_prove_hop_limit"
			return errors.New("fake hop limit unverified")
		}
		if !result.UDPOrder {
			result.Reason = "udp_packets_do_not_prove_order_tuple"
			return errors.New("UDP unverified")
		}
	}
	return nil
}

func udpAssociation(address, secret string) (net.Conn, *net.UDPConn, error) {
	control, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		return nil, nil, err
	}
	failed := true
	defer func() {
		if failed {
			control.Close()
		}
	}()
	_ = control.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = control.Write([]byte{5, 1, 2}); err != nil {
		return nil, nil, err
	}
	var authReply [2]byte
	if _, err = io.ReadFull(control, authReply[:]); err != nil || authReply != [2]byte{5, 2} {
		return nil, nil, errors.New("private auth method")
	}
	auth := append([]byte{1, 7}, []byte("fixture")...)
	auth = append(auth, byte(len(secret)))
	auth = append(auth, secret...)
	if _, err = control.Write(auth); err != nil {
		return nil, nil, err
	}
	if _, err = io.ReadFull(control, authReply[:]); err != nil || authReply != [2]byte{1, 0} {
		return nil, nil, errors.New("private auth")
	}
	if _, err = control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return nil, nil, err
	}
	var reply [10]byte
	if _, err = io.ReadFull(control, reply[:]); err != nil || reply[0] != 5 || reply[1] != 0 || reply[3] != 1 || reply[4] != 127 || reply[5] != 0 || reply[6] != 0 || reply[7] != 1 {
		return nil, nil, errors.New("private UDP association")
	}
	port := binary.BigEndian.Uint16(reply[8:])
	if port == 0 {
		return nil, nil, errors.New("private UDP port")
	}
	socket, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		return nil, nil, err
	}
	_ = socket.SetDeadline(time.Now().Add(3 * time.Second))
	failed = false
	return control, socket, nil
}
