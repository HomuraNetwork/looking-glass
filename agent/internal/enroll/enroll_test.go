package enroll

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"hlg/internal/config"
	"hlg/internal/runtime"
)

func TestClientEnrollsAndStoresActiveConfig(t *testing.T) {
	dir := t.TempDir()
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_lg/enroll" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.EnrollToken != "localtest" || req.Version != runtime.Version {
			t.Fatalf("request = %#v", req)
		}
		if req.BuildID != runtime.BuildID {
			t.Fatalf("build_id = %q, want %q", req.BuildID, runtime.BuildID)
		}
		_ = json.NewEncoder(w).Encode(Response{
			Status: "active",
			NodeID: "testnode01",
			Config: config.SignedBundle{
				Version: 1,
				NodeID:  "testnode01",
				Domain:  "testnode01.lgtest-node.example",
				Features: map[string]bool{
					"download": true,
				},
			},
		})
	}))
	defer controller.Close()

	client := NewClient(config.Config{
		Controller:  controller.URL,
		EnrollToken: "localtest",
		NodeID:      "testnode01",
		DataDir:     dir,
	})
	resp, err := client.EnrollOnce(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != "active" || resp.Config.Domain == "" {
		t.Fatalf("response = %#v", resp)
	}
	if _, err := os.Stat(filepath.Join(dir, "config.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "agent-identity.json")); err != nil {
		t.Fatal(err)
	}
}

func TestClientBootstrapsWithInitTokenAndStoresNodeToken(t *testing.T) {
	dir := t.TempDir()
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_lg/control/config" || r.Method != http.MethodPost {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("authorization"); got != "Bearer lginit_test" {
			t.Fatalf("authorization = %q", got)
		}
		var req BootstrapRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.DetectedIPv4 != "203.0.113.10" || req.DetectedIPv6 != "2001:db8::10" {
			t.Fatalf("bootstrap request = %#v", req)
		}
		_ = json.NewEncoder(w).Encode(BootstrapResponse{
			Status:    "active",
			NodeID:    "edge01",
			NodeToken: "lgnode_test",
			Config: config.SignedBundle{
				Version: 2,
				NodeID:  "edge01",
				Domain:  "edge01.example.net",
			},
		})
	}))
	defer controller.Close()

	client := NewClient(config.Config{
		Controller: controller.URL,
		InitToken:  "lginit_test",
		NodeID:     "edge01",
		DataDir:    dir,
		PublicIPv4: "203.0.113.10",
		PublicIPv6: "2001:db8::10",
	})
	resp, err := client.BootstrapOnce(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if resp.NodeToken != "lgnode_test" || resp.Config.Domain != "edge01.example.net" {
		t.Fatalf("response = %#v", resp)
	}
	token, err := LoadNodeToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	if token != "lgnode_test" {
		t.Fatalf("stored node token = %q", token)
	}
	if _, err := os.Stat(filepath.Join(dir, "config.json")); err != nil {
		t.Fatal(err)
	}
}

func TestClientReportsStoredConfigVersionOnPull(t *testing.T) {
	dir := t.TempDir()
	// Seed the config the agent is "currently serving" (version 7).
	seeder := NewClient(config.Config{DataDir: dir})
	if err := seeder.StoreConfig(config.SignedBundle{Version: 7, NodeID: "edge01", Domain: "edge01.example.net"}); err != nil {
		t.Fatal(err)
	}

	var reported string
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reported = r.URL.Query().Get("config_version")
		_ = json.NewEncoder(w).Encode(config.SignedBundle{Version: 8, NodeID: "edge01", Domain: "edge01.example.net"})
	}))
	defer controller.Close()

	puller := NewClient(config.Config{
		Controller: controller.URL,
		NodeToken:  "lgnode_test",
		NodeID:     "edge01",
		DataDir:    dir,
	})
	if _, err := puller.PullConfig(t.Context()); err != nil {
		t.Fatal(err)
	}
	// The pull reports the version it is currently serving, so the controller
	// can tell whether this node has picked up the latest config.
	if reported != "7" {
		t.Fatalf("config_version query = %q, want 7", reported)
	}
}

func TestClientPullsConfigWithNodeToken(t *testing.T) {
	dir := t.TempDir()
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_lg/control/config" || r.Method != http.MethodGet {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("authorization"); got != "Bearer lgnode_test" {
			t.Fatalf("authorization = %q", got)
		}
		if got := r.URL.Query().Get("node"); got != "edge01" {
			t.Fatalf("node query = %q", got)
		}
		if got := r.URL.Query().Get("detected_ipv4"); got != "203.0.113.10" {
			t.Fatalf("detected_ipv4 query = %q", got)
		}
		if got := r.URL.Query().Get("detected_ipv6"); got != "2001:db8::10" {
			t.Fatalf("detected_ipv6 query = %q", got)
		}
		_ = json.NewEncoder(w).Encode(config.SignedBundle{
			Version: 3,
			NodeID:  "edge01",
			Domain:  "edge01-new.example.net",
		})
	}))
	defer controller.Close()

	client := NewClient(config.Config{
		Controller: controller.URL,
		NodeToken:  "lgnode_test",
		NodeID:     "edge01",
		DataDir:    dir,
		PublicIPv4: "203.0.113.10",
		PublicIPv6: "2001:db8::10",
	})
	bundle, err := client.PullConfig(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Domain != "edge01-new.example.net" {
		t.Fatalf("bundle = %#v", bundle)
	}
	if _, err := os.Stat(filepath.Join(dir, "config.json")); err != nil {
		t.Fatal(err)
	}
}

func TestClientPullsCertificateBundleWithNodeToken(t *testing.T) {
	dir := t.TempDir()
	identity, err := loadOrCreateIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	expected := config.CertificateBundle{
		Version:       4,
		NodeID:        "edge01",
		Domain:        "edge01.example.net",
		CertExpiresAt: 1893456000,
		CertPEM:       "cert",
		KeyPEM:        "key",
	}
	body := encryptedEnvelopeForTest(t, identity.EncryptionPublicKey, expected)
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_lg/control/cert-bundle" || r.Method != http.MethodGet {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("authorization"); got != "Bearer lgnode_test" {
			t.Fatalf("authorization = %q", got)
		}
		if got := r.URL.Query().Get("node"); got != "edge01" {
			t.Fatalf("node query = %q", got)
		}
		_, _ = w.Write(body)
	}))
	defer controller.Close()

	client := NewClient(config.Config{
		Controller: controller.URL,
		NodeToken:  "lgnode_test",
		NodeID:     "edge01",
		DataDir:    dir,
	})
	bundle, err := client.PullCertBundle(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if bundle.NodeID != "edge01" || bundle.CertExpiresAt != 1893456000 {
		t.Fatalf("bundle = %#v", bundle)
	}
}

func TestClientRejectsPlaintextCertificateBundle(t *testing.T) {
	// A plaintext bundle skips ECDH and would let anyone able to terminate the
	// (self-signed) controller TLS inject a certificate bundle. It must be
	// rejected, not silently accepted.
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"version":1,"node_id":"edge01","domain":"edge01.example.net","cert_pem":"cert","key_pem":"key"}`))
	}))
	defer controller.Close()

	client := NewClient(config.Config{Controller: controller.URL, NodeToken: "lgnode_test", NodeID: "edge01", DataDir: t.TempDir()})
	if _, err := client.PullCertBundle(t.Context()); err == nil {
		t.Fatal("expected a plaintext certificate bundle to be rejected")
	}
}

func TestClientRefusesControllerRedirects(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("agent followed a redirect to %s", r.URL.Path)
	}))
	defer target.Close()
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/_lg/enroll", http.StatusFound)
	}))
	defer controller.Close()

	client := NewClient(config.Config{Controller: controller.URL, EnrollToken: "localtest", NodeID: "edge01", DataDir: t.TempDir()})
	if _, err := client.EnrollOnce(t.Context()); err == nil {
		t.Fatal("expected the redirect to be refused")
	}
}

func TestClientPullsEncryptedCertificateBundleWithNodeToken(t *testing.T) {
	dir := t.TempDir()
	identity, err := loadOrCreateIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	expected := config.CertificateBundle{
		Version:       5,
		NodeID:        "edge01",
		Domain:        "edge01.example.net",
		CertExpiresAt: 1893456000,
		CertPEM:       "cert",
		KeyPEM:        "key",
	}
	body := encryptedEnvelopeForTest(t, identity.EncryptionPublicKey, expected)
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_lg/control/cert-bundle" || r.Method != http.MethodGet {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("authorization"); got != "Bearer lgnode_test" {
			t.Fatalf("authorization = %q", got)
		}
		_, _ = w.Write(body)
	}))
	defer controller.Close()

	client := NewClient(config.Config{
		Controller: controller.URL,
		NodeToken:  "lgnode_test",
		NodeID:     "edge01",
		DataDir:    dir,
	})
	bundle, err := client.PullCertBundle(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if bundle.NodeID != expected.NodeID || bundle.KeyPEM != expected.KeyPEM || bundle.CertPEM != expected.CertPEM {
		t.Fatalf("bundle = %#v", bundle)
	}
}

func TestClientTreatsMissingCertificateBundleAsNotFound(t *testing.T) {
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer controller.Close()

	client := NewClient(config.Config{
		Controller: controller.URL,
		NodeToken:  "lgnode_test",
		NodeID:     "edge01",
		DataDir:    t.TempDir(),
	})
	if _, err := client.PullCertBundle(t.Context()); err != ErrCertBundleNotFound {
		t.Fatalf("err = %v", err)
	}
}

func TestClientCapturesNodeBundleIDFromPullHeader(t *testing.T) {
	dir := t.TempDir()
	identity, err := loadOrCreateIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	body := encryptedEnvelopeForTest(t, identity.EncryptionPublicKey, config.CertificateBundle{
		Version:       1,
		NodeID:        "edge01",
		Domain:        "edge01.example.net",
		CertExpiresAt: 1893456000,
		CertPEM:       "cert",
		KeyPEM:        "key",
	})
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-lg-node-bundle-id", "ncb_abc123")
		_, _ = w.Write(body)
	}))
	defer controller.Close()

	client := NewClient(config.Config{Controller: controller.URL, NodeToken: "lgnode_test", NodeID: "edge01", DataDir: dir})
	bundle, err := client.PullCertBundle(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if bundle.NodeBundleID != "ncb_abc123" {
		t.Fatalf("node bundle id = %q", bundle.NodeBundleID)
	}
}

func TestClientAckCertBundleReportsStatus(t *testing.T) {
	type ack struct {
		path   string
		method string
		auth   string
		body   map[string]any
	}
	var got ack
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.path = r.URL.Path
		got.method = r.Method
		got.auth = r.Header.Get("authorization")
		_ = json.NewDecoder(r.Body).Decode(&got.body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer controller.Close()

	client := NewClient(config.Config{Controller: controller.URL, NodeToken: "lgnode_test", NodeID: "edge01", DataDir: t.TempDir()})

	// A successful apply acknowledges "applied".
	if err := client.AckCertBundle(t.Context(), "ncb_ok", nil); err != nil {
		t.Fatal(err)
	}
	if got.path != "/_lg/control/cert/ack" || got.method != http.MethodPost || got.auth != "Bearer lgnode_test" {
		t.Fatalf("ack request = %#v", got)
	}
	if got.body["node_bundle_id"] != "ncb_ok" || got.body["status"] != "applied" {
		t.Fatalf("ack body = %#v", got.body)
	}

	// A failed apply reports the reason so the controller keeps it retryable.
	if err := client.AckCertBundle(t.Context(), "ncb_bad", fmt.Errorf("decrypt failed: bad key")); err != nil {
		t.Fatal(err)
	}
	if got.body["status"] != "failed" || got.body["error"] == "" {
		t.Fatalf("failure ack body = %#v", got.body)
	}

	// An empty bundle id is a no-op (nothing to acknowledge).
	if err := client.AckCertBundle(t.Context(), "", nil); err != nil {
		t.Fatalf("empty ack err = %v", err)
	}
}

func encryptedEnvelopeForTest(t *testing.T, publicKey string, bundle config.CertificateBundle) []byte {
	t.Helper()
	recipientBytes, err := base64.RawURLEncoding.DecodeString(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := ecdh.P256().NewPublicKey(recipientBytes)
	if err != nil {
		t.Fatal(err)
	}
	ephemeral, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := ephemeral.ECDH(recipient)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes := sha256.Sum256(shared)
	block, err := aes.NewCipher(keyBytes[:])
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, aead.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}
	plaintext, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	envelope := certificateEnvelope{
		Alg:        "ECDH-P256+A256GCM",
		EPK:        base64.RawURLEncoding.EncodeToString(ephemeral.PublicKey().Bytes()),
		IV:         base64.RawURLEncoding.EncodeToString(iv),
		Ciphertext: base64.RawURLEncoding.EncodeToString(aead.Seal(nil, iv, plaintext, nil)),
	}
	out, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestLoadBootstrapReadsCurlWrittenBootstrapFile(t *testing.T) {
	dir := t.TempDir()
	raw := []byte(`{
		"status": "active",
		"node_id": "edge01",
		"node_token": "lgnode_from_bootstrap",
		"config": {
			"version": 4,
			"node_id": "edge01",
			"domain": "edge01.example.net"
		}
	}`)
	if err := os.WriteFile(filepath.Join(dir, "bootstrap.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	bootstrap, err := LoadBootstrap(dir)
	if err != nil {
		t.Fatal(err)
	}
	if bootstrap.NodeToken != "lgnode_from_bootstrap" || bootstrap.Config.Domain != "edge01.example.net" {
		t.Fatalf("bootstrap = %#v", bootstrap)
	}
}
