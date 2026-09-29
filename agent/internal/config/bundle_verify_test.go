package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestVerifyWorkerGeneratedBundleFixture(t *testing.T) {
	path := os.Getenv("LG_WORKER_BUNDLE_FIXTURE")
	if path == "" {
		t.Skip("fixture supplied by worker cross-language test")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var bundles []SignedBundle
	if err := json.Unmarshal(raw, &bundles); err != nil {
		t.Fatal(err)
	}
	if len(bundles) != 3 {
		t.Fatalf("got %d worker bundles, want 3", len(bundles))
	}
	for _, bundle := range bundles {
		if bundle.Limits.DownloadMaxRequestsPerToken != 17 || bundle.Limits.DownloadMaxBytesMultiplier != 9 {
			t.Fatal("download budgets missing")
		}
		if err := VerifySignedBundle(bundle, bundle.NodeID, time.Now()); err != nil {
			t.Fatalf("worker bundle rejected: %v", err)
		}
		bundle.Domain += ".tampered"
		if err := VerifySignedBundle(bundle, bundle.NodeID, time.Now()); err != ErrBundleSignature {
			t.Fatalf("tampered worker bundle err = %v", err)
		}
	}
}

func TestVerifyLegacyWireGuardVariants(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	base := SignedBundle{Version: 1, NodeID: "legacy", Domain: "legacy.example", IssuedAt: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix(), Features: map[string]bool{"download": true}, Limits: Defaults().Limits, ConfigKID: "cfg", Keyset: []Key{{KID: "cfg", Alg: "Ed25519", Use: "config_verify", PublicKey: base64.RawURLEncoding.EncodeToString(pub)}}}
	base.Limits.DownloadMaxRequestsPerToken = 0
	base.Limits.DownloadMaxBytesMultiplier = 0
	for _, tc := range []struct {
		name      string
		guard     *bool
		withGuard bool
	}{{"null", nil, true}, {"true", boolPtr(true), true}, {"false", boolPtr(false), true}, {"absent", nil, false}} {
		t.Run(tc.name, func(t *testing.T) {
			b := base
			b.Limits.GuardPrivateIP = tc.guard
			payload, err := legacyBundleSigningPayload(b, tc.withGuard)
			if err != nil {
				t.Fatal(err)
			}
			b.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, payload))
			if err := VerifySignedBundle(b, b.NodeID, now); err != nil {
				t.Fatal(err)
			}
		})
	}
	b := base
	payload, err := legacyBundleSigningPayload(b, false)
	if err != nil {
		t.Fatal(err)
	}
	b.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, payload))
	b.Limits.GuardPrivateIP = boolPtr(false)
	if err := VerifySignedBundle(b, b.NodeID, now); err != ErrBundleSignature {
		t.Fatalf("appended guard accepted: %v", err)
	}
	b = base
	payload, err = legacyBundleSigningPayload(b, false)
	if err != nil {
		t.Fatal(err)
	}
	b.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, payload))
	b.Limits.DownloadMaxRequestsPerToken = 1
	if err := VerifySignedBundle(b, b.NodeID, now); err != ErrBundleSignature {
		t.Fatalf("appended budget accepted: %v", err)
	}
}

func boolPtr(value bool) *bool { return &value }

func TestVerifySignedBundleChecksSignatureNodeAndExpiry(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	bundle := SignedBundle{
		Version:   1,
		NodeID:    "testnode01",
		Domain:    "testnode01.lgtest-node.example",
		IssuedAt:  now.Add(-time.Minute).Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		Features:  map[string]bool{"download": true},
		Limits:    Defaults().Limits,
		ConfigKID: "config-kid-a",
		Keyset: []Key{
			{KID: "config-kid-a", Alg: "Ed25519", Use: "config_verify", PublicKey: base64.RawURLEncoding.EncodeToString(pub)},
			{KID: "kid-a", Alg: "Ed25519", Use: "token_verify", PublicKey: "abc"},
		},
	}
	payload, err := BundleSigningPayload(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundle.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, payload))

	if err := VerifySignedBundle(bundle, "testnode01", now); err != nil {
		t.Fatal(err)
	}
	if err := VerifySignedBundle(bundle, "other-node", now); err != ErrBundleWrongNode {
		t.Fatalf("wrong node err = %v", err)
	}
	if err := VerifySignedBundle(bundle, "testnode01", now.Add(2*time.Hour)); err != ErrBundleExpired {
		t.Fatalf("expired err = %v", err)
	}

	bundle.Domain = "tampered.example"
	if err := VerifySignedBundle(bundle, "testnode01", now); err != ErrBundleSignature {
		t.Fatalf("tamper err = %v", err)
	}
}

func TestVerifySignedBundleAllowsSmallClockSkew(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(bundle SignedBundle) SignedBundle {
		t.Helper()
		payload, err := BundleSigningPayload(bundle)
		if err != nil {
			t.Fatal(err)
		}
		bundle.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, payload))
		return bundle
	}
	now := time.Now()
	bundle := SignedBundle{
		Version:   1,
		NodeID:    "testnode01",
		Domain:    "testnode01.lgtest-node.example",
		IssuedAt:  now.Add(2 * time.Minute).Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		Features:  map[string]bool{"download": true},
		Limits:    Defaults().Limits,
		ConfigKID: "config-kid-a",
		Keyset: []Key{
			{KID: "config-kid-a", Alg: "Ed25519", Use: "config_verify", PublicKey: base64.RawURLEncoding.EncodeToString(pub)},
		},
	}
	if err := VerifySignedBundle(sign(bundle), "testnode01", now); err != nil {
		t.Fatalf("within skew err = %v", err)
	}

	bundle.IssuedAt = now.Add(signedBundleClockSkew + time.Second).Unix()
	if err := VerifySignedBundle(sign(bundle), "testnode01", now); err != ErrBundleNotYet {
		t.Fatalf("beyond skew err = %v", err)
	}
}

func TestVerifySignedBundleRejectsStaleButUnexpiredBundle(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	// Signed long ago but still within its ExpiresAt: a replay of an old bundle
	// must be rejected so it cannot roll the node back to stale config.
	bundle := SignedBundle{
		Version:   1,
		NodeID:    "testnode01",
		Domain:    "testnode01.lgtest-node.example",
		IssuedAt:  now.Add(-maxSignedBundleAge - time.Hour).Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		Features:  map[string]bool{"download": true},
		Limits:    Defaults().Limits,
		ConfigKID: "config-kid-a",
		Keyset: []Key{
			{KID: "config-kid-a", Alg: "Ed25519", Use: "config_verify", PublicKey: base64.RawURLEncoding.EncodeToString(pub)},
		},
	}
	payload, err := BundleSigningPayload(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundle.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, payload))
	if err := VerifySignedBundle(bundle, "testnode01", now); err != ErrBundleStale {
		t.Fatalf("stale bundle err = %v, want ErrBundleStale", err)
	}

	// A bundle issued within the window is still accepted.
	bundle.IssuedAt = now.Add(-time.Hour).Unix()
	payload, _ = BundleSigningPayload(bundle)
	bundle.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, payload))
	if err := VerifySignedBundle(bundle, "testnode01", now); err != nil {
		t.Fatalf("fresh bundle err = %v", err)
	}
}

func TestVerifySignedBundleRequiresConfigKIDAndConfigVerifyKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(bundle SignedBundle) SignedBundle {
		t.Helper()
		payload, err := BundleSigningPayload(bundle)
		if err != nil {
			t.Fatal(err)
		}
		bundle.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, payload))
		return bundle
	}
	base := SignedBundle{
		Version:   1,
		NodeID:    "testnode01",
		Domain:    "testnode01.lgtest-node.example",
		IssuedAt:  time.Now().Add(-time.Minute).Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Features:  map[string]bool{"download": true},
		Limits:    Defaults().Limits,
		ConfigKID: "config-kid-a",
		Keyset: []Key{
			{KID: "config-kid-a", Alg: "Ed25519", Use: "config_verify", PublicKey: base64.RawURLEncoding.EncodeToString(pub)},
		},
	}

	missingKID := base
	missingKID.ConfigKID = ""
	if err := VerifySignedBundle(sign(missingKID), "testnode01", time.Now()); err != ErrBundleConfigKID {
		t.Fatalf("missing config kid err = %v", err)
	}

	missingConfigKey := base
	missingConfigKey.Keyset = []Key{
		{KID: "config-kid-a", Alg: "Ed25519", Use: "token_verify", PublicKey: base64.RawURLEncoding.EncodeToString(pub)},
	}
	if err := VerifySignedBundle(sign(missingConfigKey), "testnode01", time.Now()); err != ErrBundleConfigKey {
		t.Fatalf("missing config key err = %v", err)
	}
}
