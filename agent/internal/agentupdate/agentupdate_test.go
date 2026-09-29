package agentupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hlg/internal/config"
)

func testDescriptor(nodeID, buildID string, now time.Time, key ed25519.PrivateKey) Descriptor {
	d := Descriptor{
		BuildID:   buildID,
		Target:    "hlg-agent-linux-amd64",
		SHA256:    strings.Repeat("a", 64),
		Size:      1234,
		Path:      "/_agent/binary/hlg-agent-linux-amd64",
		NodeID:    nodeID,
		ExpiresAt: now.Add(10 * time.Minute).Unix(),
	}
	d.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(SigningInput(d))))
	return d
}

func TestVerifyDescriptorAcceptsSignedPayload(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	d := testDescriptor("node-1", "abc1234", time.Now(), priv)
	if err := VerifyDescriptor(d, "node-1", time.Now(), pub); err != nil {
		t.Fatalf("expected valid descriptor, got %v", err)
	}
}

func TestVerifyDescriptorRejectsTampering(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()

	t.Run("wrong sha", func(t *testing.T) {
		d := testDescriptor("node-1", "abc1234", now, priv)
		d.SHA256 = strings.Repeat("b", 64)
		if err := VerifyDescriptor(d, "node-1", now, pub); !errors.Is(err, ErrDescriptorSignature) {
			t.Fatalf("want ErrDescriptorSignature, got %v", err)
		}
	})

	t.Run("wrong node", func(t *testing.T) {
		d := testDescriptor("node-2", "abc1234", now, priv)
		if err := VerifyDescriptor(d, "node-1", now, pub); !errors.Is(err, ErrDescriptorNode) {
			t.Fatalf("want ErrDescriptorNode, got %v", err)
		}
	})

	t.Run("expired", func(t *testing.T) {
		d := testDescriptor("node-1", "abc1234", now.Add(-time.Hour), priv)
		d.ExpiresAt = now.Add(-20 * time.Minute).Unix()
		d.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(SigningInput(d))))
		if err := VerifyDescriptor(d, "node-1", now, pub); !errors.Is(err, ErrDescriptorExpired) {
			t.Fatalf("want ErrDescriptorExpired, got %v", err)
		}
	})

	t.Run("server signing_input mismatch", func(t *testing.T) {
		d := testDescriptor("node-1", "abc1234", now, priv)
		d.SigningInput = "hlg-agent-release\nforged"
		if err := VerifyDescriptor(d, "node-1", now, pub); !errors.Is(err, ErrDescriptorSignature) {
			t.Fatalf("want ErrDescriptorSignature, got %v", err)
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		d := testDescriptor("node-1", "abc1234", now, priv)
		otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
		if err := VerifyDescriptor(d, "node-1", now, otherPub); !errors.Is(err, ErrDescriptorSignature) {
			t.Fatalf("want ErrDescriptorSignature, got %v", err)
		}
	})
}

func TestConfigVerifyKeySelectsConfigUseOnly(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	bundle := config.SignedBundle{
		ConfigKID: "cfg",
		Keyset: []config.Key{
			{KID: "cfg", Alg: "Ed25519", Use: "config_verify", PublicKey: base64.RawURLEncoding.EncodeToString(pub)},
			{KID: "tok", Alg: "Ed25519", Use: "token_verify", PublicKey: base64.RawURLEncoding.EncodeToString(pub)},
		},
	}
	got, err := ConfigVerifyKey(bundle, "cfg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.Equal(pub) {
		t.Fatalf("key mismatch")
	}
	// A key that exists but is not config_verify must be refused.
	if _, err := ConfigVerifyKey(bundle, "tok"); err == nil {
		t.Fatalf("expected token_verify key to be refused as a release key")
	}
}

func TestInstallBinaryKeepsBackupAndRollsBack(t *testing.T) {
	dir := t.TempDir()
	current := filepath.Join(dir, "hlg-agent")
	if err := os.WriteFile(current, []byte("old-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	newBinary := filepath.Join(dir, ".hlg-agent.new")
	if err := os.WriteFile(newBinary, []byte("new-binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := installBinary(newBinary, current, nil); err != nil {
		t.Fatalf("installBinary: %v", err)
	}
	if body, _ := os.ReadFile(current); string(body) != "new-binary" {
		t.Fatalf("current = %q, want new-binary", body)
	}
	if body, _ := os.ReadFile(current + ".bak"); string(body) != "old-binary" {
		t.Fatalf("backup = %q, want old-binary", body)
	}

	if err := rollbackBinary(current); err != nil {
		t.Fatalf("rollbackBinary: %v", err)
	}
	if body, _ := os.ReadFile(current); string(body) != "old-binary" {
		t.Fatalf("after rollback current = %q, want old-binary", body)
	}
}

func TestRunVerifiesAndInstallsOverHTTP(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	binaryBody := []byte("fresh-agent-binary")
	sum := sha256.Sum256(binaryBody)

	descriptor := testDescriptor("node-1", "newbuild", now, priv)
	descriptor.SHA256 = hex.EncodeToString(sum[:])
	descriptor.Size = int64(len(binaryBody))
	descriptor.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(SigningInput(descriptor))))

	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("authorization")
		switch r.URL.Path {
		case "/_agent/update":
			_ = json.NewEncoder(w).Encode(descriptor)
		case "/_agent/binary/hlg-agent-linux-amd64":
			_, _ = w.Write(binaryBody)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	installDir := t.TempDir()
	current := filepath.Join(installDir, "hlg-agent")
	if err := os.WriteFile(current, []byte("stale"), 0o755); err != nil {
		t.Fatal(err)
	}

	bundlePath := filepath.Join(installDir, "data", "config.json")
	if err := os.MkdirAll(filepath.Dir(bundlePath), 0o700); err != nil {
		t.Fatal(err)
	}
	bundle := config.SignedBundle{
		NodeID:    "node-1",
		ConfigKID: "cfg",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		Keyset: []config.Key{
			{KID: "cfg", Alg: "Ed25519", Use: "config_verify", PublicKey: base64.RawURLEncoding.EncodeToString(pub)},
		},
	}
	signBundle(t, &bundle, priv)
	body, _ := json.Marshal(bundle)
	if err := os.WriteFile(bundlePath, body, 0o600); err != nil {
		t.Fatal(err)
	}

	restarted := false
	result, err := Run(context.Background(), Options{
		Controller:     server.URL,
		NodeToken:      "lgnode_test",
		NodeID:         "node-1",
		DataDir:        filepath.Join(installDir, "data"),
		InstallDir:     installDir,
		BinaryName:     "hlg-agent",
		Arch:           "amd64",
		CurrentBuildID: "oldbuild",
		Restart:        func() error { restarted = true; return nil },
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !result.Updated || result.ReleaseBuildID != "newbuild" || result.ReleaseSHA256 != descriptor.SHA256 {
		t.Fatalf("result = %+v", result)
	}
	if gotAuth != "Bearer lgnode_test" {
		t.Fatalf("authorization = %q", gotAuth)
	}
	if !restarted {
		t.Fatalf("expected service restart")
	}
	if got, _ := os.ReadFile(current); string(got) != string(binaryBody) {
		t.Fatalf("binary not replaced: %q", got)
	}
}

func TestRunSkipsWhenAlreadyCurrent(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	descriptor := testDescriptor("node-1", "samebuild", now, priv)

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		_ = json.NewEncoder(w).Encode(descriptor)
	}))
	defer server.Close()

	installDir := t.TempDir()
	bundlePath := filepath.Join(installDir, "data", "config.json")
	if err := os.MkdirAll(filepath.Dir(bundlePath), 0o700); err != nil {
		t.Fatal(err)
	}
	bundle := config.SignedBundle{
		NodeID: "node-1", ConfigKID: "cfg", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
		Keyset: []config.Key{{KID: "cfg", Alg: "Ed25519", Use: "config_verify", PublicKey: base64.RawURLEncoding.EncodeToString(pub)}},
	}
	signBundle(t, &bundle, priv)
	body, _ := json.Marshal(bundle)
	_ = os.WriteFile(bundlePath, body, 0o600)

	result, err := Run(context.Background(), Options{
		Controller:     server.URL,
		NodeToken:      "lgnode_test",
		NodeID:         "node-1",
		DataDir:        filepath.Join(installDir, "data"),
		InstallDir:     installDir,
		BinaryName:     "hlg-agent",
		Arch:           "amd64",
		CurrentBuildID: "samebuild",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !result.UpToDate || result.Updated {
		t.Fatalf("result = %+v", result)
	}
	if requests != 1 {
		t.Fatalf("expected only the descriptor request, got %d requests", requests)
	}
}

func TestRunRejectsDigestMismatch(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	descriptor := testDescriptor("node-1", "newbuild", now, priv)
	descriptor.SHA256 = strings.Repeat("0", 64)
	descriptor.Size = 5
	descriptor.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(SigningInput(descriptor))))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_agent/update" {
			_ = json.NewEncoder(w).Encode(descriptor)
			return
		}
		_, _ = w.Write([]byte("xxxxx"))
	}))
	defer server.Close()

	installDir := t.TempDir()
	bundlePath := filepath.Join(installDir, "data", "config.json")
	if err := os.MkdirAll(filepath.Dir(bundlePath), 0o700); err != nil {
		t.Fatal(err)
	}
	bundle := config.SignedBundle{
		NodeID: "node-1", ConfigKID: "cfg", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
		Keyset: []config.Key{{KID: "cfg", Alg: "Ed25519", Use: "config_verify", PublicKey: base64.RawURLEncoding.EncodeToString(pub)}},
	}
	signBundle(t, &bundle, priv)
	body, _ := json.Marshal(bundle)
	_ = os.WriteFile(bundlePath, body, 0o600)

	_, err := Run(context.Background(), Options{
		Controller: server.URL, NodeToken: "t", NodeID: "node-1",
		DataDir: filepath.Join(installDir, "data"), InstallDir: installDir,
		BinaryName: "hlg-agent", Arch: "amd64", CurrentBuildID: "oldbuild",
	})
	if !errors.Is(err, ErrDownloadDigest) {
		t.Fatalf("want ErrDownloadDigest, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(installDir, "hlg-agent")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("binary must not be created on digest failure")
	}
}

// signBundle signs a bundle with the config key so loadVerifiedBundle trusts it.
func signBundle(t *testing.T, bundle *config.SignedBundle, key ed25519.PrivateKey) {
	t.Helper()
	payload, err := config.BundleSigningPayload(*bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundle.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, payload))
}
