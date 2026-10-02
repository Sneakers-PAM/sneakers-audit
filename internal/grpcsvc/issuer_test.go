// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// testIssuer is a local OIDC issuer over TLS (discovery and a JWKS) with an
// RSA key generated in the test, so the real verifier checks real tokens.
type testIssuer struct {
	URL    string
	CAFile string
	key    *rsa.PrivateKey
}

const testKid = "test-1"

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	i := &testIssuer{key: key}
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": i.URL, "jwks_uri": i.URL + "/openid/v1/jwks"})
	})
	mux.HandleFunc("/openid/v1/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": testKid, "use": "sig",
			"n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	i.URL = srv.URL
	i.CAFile = filepath.Join(t.TempDir(), "issuer-ca.pem")
	if err := os.WriteFile(i.CAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	return i
}

// token returns a valid projected ServiceAccount token for namespace/sa.
func (i *testIssuer) token(t *testing.T, namespace, sa string) string {
	t.Helper()
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": i.URL,
		"aud": []string{"sneakers"},
		"sub": "system:serviceaccount:" + namespace + ":" + sa,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
		"kubernetes.io": map[string]any{
			"namespace":      namespace,
			"serviceaccount": map[string]any{"name": sa, "uid": "00000000-0000-0000-0000-000000000001"},
		},
	})
	tok.Header["kid"] = testKid
	s, err := tok.SignedString(i.key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}
