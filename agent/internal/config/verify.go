package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

const signedBundleClockSkew = 5 * time.Minute

// maxSignedBundleAge bounds how old a still-unexpired bundle may be. Without a
// lower bound, an operator/controller could replay a very old but unexpired
// bundle to roll a node back to stale config. Set generously above any real
// bundle lifetime so normal rotation is unaffected.
const maxSignedBundleAge = 30 * 24 * time.Hour

var (
	ErrBundleSignature = errors.New("bundle signature invalid")
	ErrBundleWrongNode = errors.New("bundle node mismatch")
	ErrBundleExpired   = errors.New("bundle expired")
	ErrBundleStale     = errors.New("bundle too old")
	ErrBundleNotYet    = errors.New("bundle not yet valid")
	ErrBundleConfigKID = errors.New("bundle config_kid missing")
	ErrBundleConfigKey = errors.New("bundle config_verify key missing")
)

func BundleSigningPayload(bundle SignedBundle) ([]byte, error) {
	bundle.Signature = ""
	return json.Marshal(bundle)
}

func VerifySignedBundle(bundle SignedBundle, nodeID string, now time.Time) error {
	if bundle.NodeID != nodeID {
		return ErrBundleWrongNode
	}
	if bundle.IssuedAt > now.Add(signedBundleClockSkew).Unix() {
		return ErrBundleNotYet
	}
	// Reject an old-but-unexpired bundle so it cannot be replayed to roll a
	// node back to stale config. Age is measured from IssuedAt, not ExpiresAt.
	if bundle.IssuedAt > 0 && bundle.IssuedAt < now.Add(-maxSignedBundleAge).Unix() {
		return ErrBundleStale
	}
	if bundle.ExpiresAt <= now.Unix() {
		return ErrBundleExpired
	}
	publicKey, err := bundleConfigPublicKey(bundle)
	if err != nil {
		return err
	}
	signature, err := base64.RawURLEncoding.DecodeString(bundle.Signature)
	if err != nil {
		return ErrBundleSignature
	}
	payload, err := BundleSigningPayload(bundle)
	if err != nil {
		return err
	}
	if ed25519.Verify(publicKey, payload, signature) {
		return nil
	}
	// Bundles issued before the download budget fields were added remain
	// valid.  Restrict the compatibility path to bundles whose new fields are
	// absent (zero after JSON unmarshalling), so it cannot silently discard a
	// signed effective setting. The signature is still checked with the same
	// trusted key; this only changes the historical canonical JSON shape.
	if bundle.Limits.DownloadMaxRequestsPerToken == 0 && bundle.Limits.DownloadMaxBytesMultiplier == 0 {
		if legacy, legacyErr := legacyBundleSigningPayload(bundle, true); legacyErr == nil && ed25519.Verify(publicKey, legacy, signature) {
			return nil
		}
		if bundle.Limits.GuardPrivateIP == nil {
			if legacy, legacyErr := legacyBundleSigningPayload(bundle, false); legacyErr == nil && ed25519.Verify(publicKey, legacy, signature) {
				return nil
			}
		}
	}
	return ErrBundleSignature
}

// legacyBundleSigningPayload reproduces the worker's pre-download-budget
// object insertion order. The first variant includes guard_private_ip (the
// short-lived tri-state rollout); the second is the older shape without it.
func legacyBundleSigningPayload(bundle SignedBundle, withGuard bool) ([]byte, error) {
	type legacyLimits struct {
		DownloadConcurrency  int      `json:"download_concurrency"`
		IperfActiveSessions  int      `json:"iperf_active_sessions"`
		JobConcurrencyPerIP  int      `json:"job_concurrency_per_ip"`
		JobTimeoutSec        int      `json:"job_timeout_sec"`
		JobMaxOutputBytes    int      `json:"job_max_output_bytes"`
		GuardPrivateIP       *bool    `json:"guard_private_ip"`
		AllowedDownloadSizes []string `json:"allowed_download_sizes"`
		IperfPortMin         int      `json:"iperf_port_min"`
		IperfPortMax         int      `json:"iperf_port_max"`
		IperfTTLSeconds      int      `json:"iperf_ttl_seconds"`
		IperfMaxDuration     int      `json:"iperf_max_duration"`
		IperfMaxParallel     int      `json:"iperf_max_parallel"`
		IperfMaxRuns         int      `json:"iperf_max_runs"`
		IperfRunBudget       int      `json:"iperf_run_budget"`
		TokenIPv4Prefix      int      `json:"token_ipv4_prefix"`
		TokenIPv6Prefix      int      `json:"token_ipv6_prefix"`
		AllowedControlTTL    int      `json:"allowed_control_ttl"`
	}
	type legacyBundle struct {
		Version    int64           `json:"version"`
		NodeID     string          `json:"node_id"`
		Domain     string          `json:"domain"`
		PublicIPv4 string          `json:"public_ipv4,omitempty"`
		PublicIPv6 string          `json:"public_ipv6,omitempty"`
		DynamicIP  bool            `json:"dynamic_ip,omitempty"`
		IssuedAt   int64           `json:"issued_at"`
		ExpiresAt  int64           `json:"expires_at"`
		Features   map[string]bool `json:"features"`
		Limits     legacyLimits    `json:"limits"`
		ConfigKID  string          `json:"config_kid"`
		Keyset     []Key           `json:"keyset"`
		Signature  string          `json:"signature"`
	}
	limits := legacyLimits{
		DownloadConcurrency:  bundle.Limits.DownloadConcurrency,
		IperfActiveSessions:  bundle.Limits.IperfActiveSessions,
		JobConcurrencyPerIP:  bundle.Limits.JobConcurrencyPerIP,
		JobTimeoutSec:        bundle.Limits.JobTimeoutSec,
		JobMaxOutputBytes:    bundle.Limits.JobMaxOutputBytes,
		AllowedDownloadSizes: bundle.Limits.AllowedDownloadSizes,
		IperfPortMin:         bundle.Limits.IperfPortMin, IperfPortMax: bundle.Limits.IperfPortMax,
		IperfTTLSeconds: bundle.Limits.IperfTTLSeconds, IperfMaxDuration: bundle.Limits.IperfMaxDuration,
		IperfMaxParallel: bundle.Limits.IperfMaxParallel, IperfMaxRuns: bundle.Limits.IperfMaxRuns,
		IperfRunBudget: bundle.Limits.IperfRunBudget, TokenIPv4Prefix: bundle.Limits.TokenIPv4Prefix,
		TokenIPv6Prefix: bundle.Limits.TokenIPv6Prefix, AllowedControlTTL: bundle.Limits.AllowedControlTTL,
	}
	if withGuard {
		limits.GuardPrivateIP = bundle.Limits.GuardPrivateIP
	} else {
		// The original worker omitted this key entirely. Use a separate type
		// because encoding/json preserves struct field order, which is part of
		// the signed wire format.
		type legacyLimitsNoGuard struct {
			DownloadConcurrency  int      `json:"download_concurrency"`
			IperfActiveSessions  int      `json:"iperf_active_sessions"`
			JobConcurrencyPerIP  int      `json:"job_concurrency_per_ip"`
			JobTimeoutSec        int      `json:"job_timeout_sec"`
			JobMaxOutputBytes    int      `json:"job_max_output_bytes"`
			AllowedDownloadSizes []string `json:"allowed_download_sizes"`
			IperfPortMin         int      `json:"iperf_port_min"`
			IperfPortMax         int      `json:"iperf_port_max"`
			IperfTTLSeconds      int      `json:"iperf_ttl_seconds"`
			IperfMaxDuration     int      `json:"iperf_max_duration"`
			IperfMaxParallel     int      `json:"iperf_max_parallel"`
			IperfMaxRuns         int      `json:"iperf_max_runs"`
			IperfRunBudget       int      `json:"iperf_run_budget"`
			TokenIPv4Prefix      int      `json:"token_ipv4_prefix"`
			TokenIPv6Prefix      int      `json:"token_ipv6_prefix"`
			AllowedControlTTL    int      `json:"allowed_control_ttl"`
		}
		type legacyBundleNoGuard struct {
			Version    int64               `json:"version"`
			NodeID     string              `json:"node_id"`
			Domain     string              `json:"domain"`
			PublicIPv4 string              `json:"public_ipv4,omitempty"`
			PublicIPv6 string              `json:"public_ipv6,omitempty"`
			DynamicIP  bool                `json:"dynamic_ip,omitempty"`
			IssuedAt   int64               `json:"issued_at"`
			ExpiresAt  int64               `json:"expires_at"`
			Features   map[string]bool     `json:"features"`
			Limits     legacyLimitsNoGuard `json:"limits"`
			ConfigKID  string              `json:"config_kid"`
			Keyset     []Key               `json:"keyset"`
			Signature  string              `json:"signature"`
		}
		noGuard := legacyLimitsNoGuard{limits.DownloadConcurrency, limits.IperfActiveSessions, limits.JobConcurrencyPerIP, limits.JobTimeoutSec, limits.JobMaxOutputBytes, limits.AllowedDownloadSizes, limits.IperfPortMin, limits.IperfPortMax, limits.IperfTTLSeconds, limits.IperfMaxDuration, limits.IperfMaxParallel, limits.IperfMaxRuns, limits.IperfRunBudget, limits.TokenIPv4Prefix, limits.TokenIPv6Prefix, limits.AllowedControlTTL}
		return json.Marshal(legacyBundleNoGuard{bundle.Version, bundle.NodeID, bundle.Domain, bundle.PublicIPv4, bundle.PublicIPv6, bundle.DynamicIP, bundle.IssuedAt, bundle.ExpiresAt, bundle.Features, noGuard, bundle.ConfigKID, bundle.Keyset, ""})
	}
	legacy := legacyBundle{bundle.Version, bundle.NodeID, bundle.Domain, bundle.PublicIPv4, bundle.PublicIPv6, bundle.DynamicIP, bundle.IssuedAt, bundle.ExpiresAt, bundle.Features, limits, bundle.ConfigKID, bundle.Keyset, ""}
	return json.Marshal(legacy)
}

func bundleConfigPublicKey(bundle SignedBundle) (ed25519.PublicKey, error) {
	if bundle.ConfigKID == "" {
		return nil, ErrBundleConfigKID
	}
	for _, item := range bundle.Keyset {
		if item.KID != bundle.ConfigKID || item.Use != "config_verify" || item.Alg != "Ed25519" {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(item.PublicKey)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, ErrBundleConfigKey
		}
		return ed25519.PublicKey(raw), nil
	}
	return nil, ErrBundleConfigKey
}
