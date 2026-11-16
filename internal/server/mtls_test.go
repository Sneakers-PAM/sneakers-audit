// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	mtls "github.com/Bugs5382/go-mtls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

// writePKI writes a CA and one certificate for localhost, signed by it, into a
// temp dir and returns the three paths.
func writePKI(t *testing.T) mtls.Files {
	t.Helper()
	dir := t.TempDir()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "audit"},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	f := mtls.Files{Cert: filepath.Join(dir, "tls.crt"), Key: filepath.Join(dir, "tls.key"), CA: filepath.Join(dir, "ca.crt")}
	for path, b := range map[string][]byte{
		f.Cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		f.Key:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		f.CA:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
	} {
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func TestMTLSFromEnv_UnsetIsPlaintext(t *testing.T) {
	p, err := MTLSFromEnv(envOf(nil), log.Nop())
	if err != nil || p != nil {
		t.Fatalf("MTLSFromEnv with nothing set = (%v, %v), want (nil, nil)", p, err)
	}
}

// A half-configured mTLS must stop the boot rather than fall back to plaintext.
func TestMTLSFromEnv_PartialFailsClosedNamingTheMissing(t *testing.T) {
	_, err := MTLSFromEnv(envOf(map[string]string{"MTLS_CERT_FILE": "/x/tls.crt"}), log.Nop())
	if err == nil {
		t.Fatal("a partial configuration must fail")
	}
	for _, want := range []string{"MTLS_KEY_FILE", "MTLS_CA_FILE"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not name %s", err, want)
		}
	}
}

func TestMTLSFromEnv_UnreadableFileFails(t *testing.T) {
	_, err := MTLSFromEnv(envOf(map[string]string{
		"MTLS_CERT_FILE": "/nonexistent/tls.crt", "MTLS_KEY_FILE": "/nonexistent/tls.key", "MTLS_CA_FILE": "/nonexistent/ca.crt",
	}), log.Nop())
	if err == nil {
		t.Fatal("unreadable files must fail")
	}
}

func TestMTLSFromEnv_Configured(t *testing.T) {
	f := writePKI(t)
	p, err := MTLSFromEnv(envOf(map[string]string{"MTLS_CERT_FILE": f.Cert, "MTLS_KEY_FILE": f.Key, "MTLS_CA_FILE": f.CA}), log.Nop())
	if err != nil || p == nil {
		t.Fatalf("MTLSFromEnv = (%v, %v), want a provider", p, err)
	}
}

func startRun(t *testing.T, port, healthPort string, opts ...grpc.ServerOption) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- RunWithHealthPort(ctx, port, healthPort, log.Nop(), nil, func(*grpc.Server) {}, opts...)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Run did not stop")
		}
	})
}

func waitDial(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.Dial("tcp", addr); err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s never listened", addr)
}

func healthCall(ctx context.Context, cc *grpc.ClientConn, service string) (healthpb.HealthCheckResponse_ServingStatus, error) {
	r, err := healthpb.NewHealthClient(cc).Check(ctx, &healthpb.HealthCheckRequest{Service: service})
	if err != nil {
		return 0, err
	}
	return r.Status, nil
}

// With mTLS on, the main port requires a client certificate, and a separate
// plain port answers health only, for the kubelet probe.
func TestRunWithHealthPort_MTLSMainPortAndPlainHealthPort(t *testing.T) {
	f := writePKI(t)
	p, err := mtls.NewProvider(f)
	if err != nil {
		t.Fatal(err)
	}
	port, hport := freePort(t), freePort(t)
	startRun(t, port, hport, p.ServerOption())
	waitDial(t, "127.0.0.1:"+port)
	waitDial(t, "127.0.0.1:"+hport)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// A caller with a certificate from the cluster CA gets through.
	good, err := grpc.NewClient("localhost:"+port, p.DialOption())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = good.Close() }()
	if st, err := healthCall(ctx, good, LivenessService); err != nil || st != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("mTLS liveness = %v, %v", st, err)
	}

	// A plaintext caller is refused on the main port.
	plain, err := grpc.NewClient("127.0.0.1:"+port, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = plain.Close() }()
	if _, err := healthCall(ctx, plain, LivenessService); err == nil {
		t.Fatal("a plaintext call to the mTLS port must fail")
	}

	// The health port is plain, and answers the health service.
	hc, err := grpc.NewClient("127.0.0.1:"+hport, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hc.Close() }()
	if st, err := healthCall(ctx, hc, LivenessService); err != nil || st != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("plain health liveness = %v, %v", st, err)
	}
	if st, err := healthCall(ctx, hc, ""); err != nil || st != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("plain health readiness = %v, %v", st, err)
	}

	// It serves nothing else: no reflection, no audit service.
	err = hc.Invoke(ctx, "/sneakers.audit.v1.AuditService/RecordEvent", &healthpb.HealthCheckRequest{}, &healthpb.HealthCheckResponse{})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("a non-health call on the health port = %v, want Unimplemented", err)
	}
}

// With no health port the server behaves as before: one port, health on it.
func TestRunWithHealthPort_NoHealthPortIsOnePort(t *testing.T) {
	port := freePort(t)
	startRun(t, port, "")
	waitDial(t, "127.0.0.1:"+port)
	cc, err := grpc.NewClient("127.0.0.1:"+port, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cc.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if st, err := healthCall(ctx, cc, LivenessService); err != nil || st != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("liveness = %v, %v", st, err)
	}
}
