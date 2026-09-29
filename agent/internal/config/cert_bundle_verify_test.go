package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"
)

func TestVerifySignedCertificateBundle(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	configBundle := SignedBundle{
		Version:   1,
		NodeID:    "edge01",
		Domain:    "edge01.example.net",
		IssuedAt:  time.Now().Add(-time.Minute).Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		ConfigKID: "config-kid-a",
		Keyset: []Key{
			{KID: "config-kid-a", Alg: "Ed25519", Use: "config_verify", PublicKey: base64.RawURLEncoding.EncodeToString(pub)},
		},
	}
	bundle := CertificateBundle{
		Version:       10,
		NodeID:        "edge01",
		Domain:        "edge01.example.net",
		IssuedAt:      time.Now().Add(-time.Minute).Unix(),
		CertExpiresAt: time.Now().Add(time.Hour).Unix(),
		CertPEM:       "cert",
		KeyPEM:        "key",
		CAPEM:         "",
		ConfigKID:     "config-kid-a",
	}
	payload, err := CertificateBundleSigningPayload(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundle.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, payload))

	if err := VerifySignedCertificateBundle(bundle, configBundle, "edge01", time.Now()); err != nil {
		t.Fatal(err)
	}
	bundle.Domain = "other.example.net"
	if err := VerifySignedCertificateBundle(bundle, configBundle, "edge01", time.Now()); err != ErrCertBundleWrongNode {
		t.Fatalf("wrong domain err = %v", err)
	}
}
