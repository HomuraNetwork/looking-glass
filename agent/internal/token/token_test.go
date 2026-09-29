package token

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"hlg/internal/config"
	"hlg/internal/keyset"
	"hlg/internal/signing"
)

func TestVerifierAcceptsValidDownloadTokenMoreThanOnce(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier := newTestVerifier(t, pub, nil)
	claims := DownloadClaims{
		BaseClaims: BaseClaims{
			Type:      "download",
			KID:       "kid-a",
			Node:      "testnode01",
			IP:        "203.0.113.44",
			IPBinding: "relaxed",
			ExpiresAt: time.Now().Add(time.Minute).Unix(),
			Nonce:     "abcdefghijklmnop",
		},
		Size: "10M",
	}

	raw, err := signing.SignCompact(claims, priv)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifier.VerifyDownload(context.Background(), raw, RequestContext{
		ClientIP: "203.0.113.99",
		NodeID:   "testnode01",
	})
	if err != nil {
		t.Fatal(err)
	}
	if verified.Size != "10M" {
		t.Fatalf("size = %q", verified.Size)
	}

	_, err = verifier.VerifyDownload(context.Background(), raw, RequestContext{
		ClientIP: "203.0.113.99",
		NodeID:   "testnode01",
	})
	if err != nil {
		t.Fatalf("second download verify err = %v", err)
	}
}

func TestVerifierRejectsJobReplay(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier := newTestVerifier(t, pub, nil)
	claims := JobClaims{
		BaseClaims: BaseClaims{
			Type:      "job",
			KID:       "kid-a",
			Node:      "testnode01",
			IP:        "203.0.113.44",
			IPBinding: "relaxed",
			ExpiresAt: time.Now().Add(time.Minute).Unix(),
			Nonce:     "jobnonceabcdefghijkl",
		},
		Tool:   "ping",
		Target: "1.1.1.1",
		IPVer:  "ipv4",
		Count:  1,
	}
	raw, err := signing.SignCompact(claims, priv)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		_, err = verifier.VerifyJob(context.Background(), raw, RequestContext{
			ClientIP: "203.0.113.99",
			NodeID:   "testnode01",
		})
	}
	if !errors.Is(err, ErrReplay) {
		t.Fatalf("job replay err = %v", err)
	}
}

func TestVerifierReturnsTypedDownloadErrors(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		mutate   func(*DownloadClaims)
		clientIP string
		want     error
	}{
		{
			name: "expired",
			mutate: func(claims *DownloadClaims) {
				claims.ExpiresAt = time.Now().Add(-time.Minute).Unix()
			},
			clientIP: "203.0.113.44",
			want:     ErrExpired,
		},
		{
			name: "wrong node",
			mutate: func(claims *DownloadClaims) {
				claims.Node = "other-node"
			},
			clientIP: "203.0.113.44",
			want:     ErrWrongNode,
		},
		{
			name: "disallowed size",
			mutate: func(claims *DownloadClaims) {
				claims.Size = "1G"
			},
			clientIP: "203.0.113.44",
			want:     ErrDisallowedSize,
		},
		{
			name: "strict ip mismatch",
			mutate: func(claims *DownloadClaims) {
				claims.IPBinding = "strict"
			},
			clientIP: "203.0.113.45",
			want:     ErrIPBinding,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := newTestVerifier(t, pub, nil)
			claims := DownloadClaims{
				BaseClaims: BaseClaims{
					Type:      "download",
					KID:       "kid-a",
					Node:      "testnode01",
					IP:        "203.0.113.44",
					IPBinding: "relaxed",
					ExpiresAt: time.Now().Add(time.Minute).Unix(),
					Nonce:     "abcdefghijklmnop" + tt.name,
				},
				Size: "10M",
			}
			tt.mutate(&claims)
			raw, err := signing.SignCompact(claims, priv)
			if err != nil {
				t.Fatal(err)
			}
			_, err = verifier.VerifyDownload(context.Background(), raw, RequestContext{
				ClientIP: tt.clientIP,
				NodeID:   "testnode01",
			})
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestVerifierRefreshesUnknownKIDOnce(t *testing.T) {
	pubA, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	refreshes := 0
	verifier := newTestVerifier(t, pubA, func(_ context.Context, kid string) ([]config.Key, error) {
		refreshes++
		if kid != "kid-b" {
			t.Fatalf("refresh kid = %q", kid)
		}
		return []config.Key{rawPublicKey("kid-b", "token_verify", pubB)}, nil
	})
	claims := JobClaims{
		BaseClaims: BaseClaims{
			Type:      "job",
			KID:       "kid-b",
			Node:      "testnode01",
			IP:        "203.0.113.44",
			IPBinding: "none",
			ExpiresAt: time.Now().Add(time.Minute).Unix(),
			Nonce:     "abcdefghijklmnop-job",
		},
		Tool:   "ping",
		Target: "1.1.1.1",
		IPVer:  "ipv4",
		Count:  4,
	}
	raw, err := signing.SignCompact(claims, privB)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifier.VerifyJob(context.Background(), raw, RequestContext{
		ClientIP: "198.51.100.1",
		NodeID:   "testnode01",
	})
	if err != nil {
		t.Fatal(err)
	}
	if refreshes != 1 || verified.Tool != "ping" {
		t.Fatalf("refreshes=%d verified=%#v", refreshes, verified)
	}
}

func TestVerifierRejectsBadSignature(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier := newTestVerifier(t, pub, nil)
	claims := DownloadClaims{
		BaseClaims: BaseClaims{
			Type:      "download",
			KID:       "kid-a",
			Node:      "testnode01",
			IP:        "203.0.113.44",
			IPBinding: "none",
			ExpiresAt: time.Now().Add(time.Minute).Unix(),
			Nonce:     "abcdefghijklmnop-bad",
		},
		Size: "10M",
	}
	raw, err := signing.SignCompact(claims, other)
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifier.VerifyDownload(context.Background(), raw, RequestContext{
		ClientIP: "203.0.113.44",
		NodeID:   "testnode01",
	})
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("err = %v", err)
	}
}

func TestNonceCacheRejectsReplayWithinTTL(t *testing.T) {
	cache := NewNonceCache(100, DefaultNonceCacheTTL)
	start := time.Unix(1780000000, 0)
	if !cache.Use("nonce-0123456789abcdef", start) {
		t.Fatal("first use of nonce rejected")
	}
	// Exactly at the old 5-minute TTL boundary the nonce is still live.
	if cache.Use("nonce-0123456789abcdef", start.Add(5*time.Minute)) {
		t.Fatal("nonce accepted again within TTL")
	}
	if !cache.Use("nonce-0123456789abcdeg", start.Add(5*time.Minute)) {
		t.Fatal("unrelated nonce rejected")
	}
	// Reuse is permitted once the entry has expired (expiresAt == now is
	// already expired).
	if !cache.Use("nonce-0123456789abcdef", start.Add(DefaultNonceCacheTTL)) {
		t.Fatal("nonce not reusable after TTL expiry")
	}
}

func TestNonceCacheEvictsExpiredEntriesBeforeLiveOldest(t *testing.T) {
	cache := NewNonceCache(3, 5*time.Minute)
	start := time.Unix(1780000000, 0)
	// Fill the cache with entries that are already expired by the time the
	// next nonce arrives, then push past capacity.
	if !cache.Use("expired-a", start) || !cache.Use("expired-b", start) || !cache.Use("expired-c", start) {
		t.Fatal("initial uses rejected")
	}
	later := start.Add(time.Minute)
	if !cache.Use("live-nonce", later) {
		t.Fatal("live nonce rejected")
	}
	if !cache.Use("overflow-nonce", later) {
		t.Fatal("use past capacity rejected instead of evicting expired entries")
	}
	// The expired entries must have been evicted first; the still-live nonce
	// survives and continues to reject replays.
	if cache.Use("live-nonce", later.Add(time.Minute)) {
		t.Fatal("live nonce was evicted while expired entries existed")
	}
	// Once the expired entries are gone, capacity eviction falls back to LRU:
	// "expired-a".."expired-c" were dropped, so "overflow-nonce" is the oldest
	// remaining entry after "live-nonce" and is evicted on the next overflow.
	if !cache.Use("fresh-nonce", later.Add(2*time.Minute)) {
		t.Fatal("use past capacity rejected with no expired entries available")
	}
	if cache.Use("overflow-nonce", later.Add(2*time.Minute)) {
		t.Fatal("overflow nonce was not LRU-evicted")
	}
}

func newTestVerifier(t *testing.T, pub ed25519.PublicKey, refresh RefreshFunc) *Verifier {
	t.Helper()
	keys, err := keyset.New([]config.Key{rawPublicKey("kid-a", "token_verify", pub)})
	if err != nil {
		t.Fatal(err)
	}
	return NewVerifier(VerifierConfig{
		NodeID:               "testnode01",
		Keyset:               keys,
		Refresh:              refresh,
		AllowedDownloadSizes: []string{"10M", "100M"},
		AllowedTools:         []string{"ping", "mtr", "traceroute", "nexttrace"},
		IPv4Prefix:           24,
		IPv6Prefix:           48,
		NonceCache:           NewNonceCache(DefaultNonceCacheCapacity, DefaultNonceCacheTTL),
	})
}

func rawPublicKey(kid, use string, pub ed25519.PublicKey) config.Key {
	return config.Key{
		KID:       kid,
		Alg:       "Ed25519",
		Use:       use,
		PublicKey: base64.RawURLEncoding.EncodeToString(pub),
	}
}
