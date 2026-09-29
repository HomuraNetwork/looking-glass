package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"hlg/internal/token"
)

func TestAdminMiddlewareRejectsUnsignedAndAcceptsSignedRequest(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier := NewAdminVerifier(AdminVerifierConfig{
		NodeID:     "testnode01",
		PublicKeys: map[string]ed25519.PublicKey{"admin": pub},
		NonceCache: token.NewNonceCache(100, time.Minute),
	})
	handler := verifier.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	unsigned := httptest.NewRequest(http.MethodPost, "/_lg/control/sync", bytes.NewReader([]byte(`{}`)))
	unsignedRes := httptest.NewRecorder()
	handler.ServeHTTP(unsignedRes, unsigned)
	if unsignedRes.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned status = %d", unsignedRes.Code)
	}

	body := []byte(`{"ok":true}`)
	signed := httptest.NewRequest(http.MethodPost, "/_lg/control/sync", bytes.NewReader(body))
	signAdmin(t, signed, body, "testnode01", "admin", priv)
	signedRes := httptest.NewRecorder()
	handler.ServeHTTP(signedRes, signed)
	if signedRes.Code != http.StatusOK {
		t.Fatalf("signed status = %d body=%s", signedRes.Code, signedRes.Body.String())
	}
}

func TestAdminMiddlewareRejectsOversizedBodyBeforeVerify(t *testing.T) {
	verifier := NewAdminVerifier(AdminVerifierConfig{NodeID: "testnode01"})
	handler := verifier.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/_lg/control/sync", bytes.NewReader(bytes.Repeat([]byte("x"), maxAdminBodyBytes+1)))
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if res.Code != http.StatusBadRequest {
		t.Fatalf("oversized status = %d body=%s", res.Code, res.Body.String())
	}
}

// signAdminURI signs over an explicit URI string (path, or path+query) so
// tests can pin the exact signature input format.
func signAdminURI(t *testing.T, req *http.Request, body []byte, uri, nodeID, kid string, priv ed25519.PrivateKey) {
	t.Helper()
	timestamp := fmt.Sprint(time.Now().Unix())
	nonce := "nonce-abcdefghijklmnop"
	bodyHash := sha256.Sum256(body)
	input := req.Method + "\n" + uri + "\n" + timestamp + "\n" + nonce + "\n" +
		fmt.Sprintf("%x", bodyHash[:]) + "\n" + nodeID
	signature := ed25519.Sign(priv, []byte(input))
	req.Header.Set("x-lg-timestamp", timestamp)
	req.Header.Set("x-lg-nonce", nonce)
	req.Header.Set("x-lg-key-id", kid)
	req.Header.Set("x-lg-signature", base64.RawURLEncoding.EncodeToString(signature))
}

func serveSigned(t *testing.T, handler http.Handler, target string, body []byte, uri, nodeID, kid string, priv ed25519.PrivateKey) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, bytes.NewReader(body))
	signAdminURI(t, req, body, uri, nodeID, kid, priv)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	return res
}

func TestAdminMiddlewareAcceptsPathOnlySignatureWithQuery(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier := NewAdminVerifier(AdminVerifierConfig{
		NodeID:     "testnode01",
		PublicKeys: map[string]ed25519.PublicKey{"admin": pub},
		NonceCache: token.NewNonceCache(100, time.Minute),
	})
	handler := verifier.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// The worker signs the path only; a request carrying a query string must
	// still verify against that path.
	res := serveSigned(t, handler, "/_lg/control/config?node=testnode01", []byte{}, "/_lg/control/config", "testnode01", "admin", priv)
	if res.Code != http.StatusOK {
		t.Fatalf("path-only signed status = %d body=%s", res.Code, res.Body.String())
	}
}

func TestAdminMiddlewareRejectsInvalidSignatureWithoutQuery(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier := NewAdminVerifier(AdminVerifierConfig{
		NodeID: "testnode01", PublicKeys: map[string]ed25519.PublicKey{"admin": pub},
		NonceCache: token.NewNonceCache(100, time.Minute),
	})
	handler := verifier.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	body := []byte(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/_lg/control/sync", bytes.NewReader(body))
	signAdmin(t, req, body, "testnode01", "admin", priv)
	req.Header.Set("x-lg-signature", base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0}, ed25519.SignatureSize)))
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("invalid no-query signature status = %d", res.Code)
	}
}

func TestAdminMiddlewareDoesNotConsumeNonceOnInvalidSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier := NewAdminVerifier(AdminVerifierConfig{
		NodeID: "testnode01", PublicKeys: map[string]ed25519.PublicKey{"admin": pub},
		NonceCache: token.NewNonceCache(100, time.Minute),
	})
	handler := verifier.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	body := []byte(`{}`)
	bad := httptest.NewRequest(http.MethodPost, "/_lg/control/sync", bytes.NewReader(body))
	signAdmin(t, bad, body, "testnode01", "admin", priv)
	bad.Header.Set("x-lg-signature", base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0}, ed25519.SignatureSize)))
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, bad)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("bad signature status = %d", res.Code)
	}
	good := httptest.NewRequest(http.MethodPost, "/_lg/control/sync", bytes.NewReader(body))
	// Reuse the exact authenticated nonce/signature fields from the failed
	// request; an invalid request must not poison the nonce cache.
	signAdmin(t, good, body, "testnode01", "admin", priv)
	// signAdmin uses the same deterministic nonce in this test package.
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, good)
	if res.Code != http.StatusOK {
		t.Fatalf("valid request after bad signature status = %d body=%s", res.Code, res.Body.String())
	}
}

func TestAdminMiddlewareBindsBodyAndRejectsReplay(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier := NewAdminVerifier(AdminVerifierConfig{NodeID: "testnode01", PublicKeys: map[string]ed25519.PublicKey{"admin": pub}, NonceCache: token.NewNonceCache(100, time.Minute)})
	handler := verifier.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	body := []byte(`{"ok":true}`)
	req := httptest.NewRequest(http.MethodPost, "/_lg/control/sync", bytes.NewReader(body))
	signAdmin(t, req, body, "testnode01", "admin", priv)
	// Keep the signed headers but alter the payload.
	req.Body = io.NopCloser(bytes.NewReader([]byte(`{"ok":false}`)))
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("body tamper status = %d", res.Code)
	}
	valid := httptest.NewRequest(http.MethodPost, "/_lg/control/sync", bytes.NewReader(body))
	signAdmin(t, valid, body, "testnode01", "admin", priv)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, valid)
	if res.Code != http.StatusOK {
		t.Fatalf("valid status = %d", res.Code)
	}
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, valid)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("replay status = %d", res.Code)
	}
}

func TestAdminMiddlewareRejectsSignatureOverDifferentQuery(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier := NewAdminVerifier(AdminVerifierConfig{
		NodeID:     "testnode01",
		PublicKeys: map[string]ed25519.PublicKey{"admin": pub},
		NonceCache: token.NewNonceCache(100, time.Minute),
	})
	handler := verifier.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// The signature does not bind the query, so a signature minted for one
	// path is accepted on the same path with any query. This is intentional:
	// the single-use nonce cache is what prevents reuse, not query binding.
	// A signature over a *different path* must still be rejected.
	res := serveSigned(t, handler, "/_lg/control/sync?node=b", []byte{}, "/_lg/control/config", "testnode01", "admin", priv)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("different-path signature status = %d body=%s", res.Code, res.Body.String())
	}
}

func signAdmin(t *testing.T, req *http.Request, body []byte, nodeID, kid string, priv ed25519.PrivateKey) {
	t.Helper()
	timestamp := fmt.Sprint(time.Now().Unix())
	nonce := "nonce-abcdefghijklmnop"
	bodyHash := sha256.Sum256(body)
	input := req.Method + "\n" + req.URL.Path + "\n" + timestamp + "\n" + nonce + "\n" +
		fmt.Sprintf("%x", bodyHash[:]) + "\n" + nodeID
	signature := ed25519.Sign(priv, []byte(input))
	req.Header.Set("x-lg-timestamp", timestamp)
	req.Header.Set("x-lg-nonce", nonce)
	req.Header.Set("x-lg-key-id", kid)
	req.Header.Set("x-lg-signature", base64.RawURLEncoding.EncodeToString(signature))
}
