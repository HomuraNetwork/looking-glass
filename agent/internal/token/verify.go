package token

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"hlg/internal/config"
	"hlg/internal/keyset"
	"hlg/internal/signing"
)

type RefreshFunc func(context.Context, string) ([]config.Key, error)

type VerifierConfig struct {
	NodeID               string
	Keyset               *keyset.Keyset
	Refresh              RefreshFunc
	AllowedDownloadSizes []string
	AllowedTools         []string
	IPv4Prefix           int
	IPv6Prefix           int
	NonceCache           *NonceCache
	Now                  func() time.Time
}

type Verifier struct {
	cfg VerifierConfig
}

func NewVerifier(cfg VerifierConfig) *Verifier {
	if cfg.NonceCache == nil {
		cfg.NonceCache = NewNonceCache(DefaultNonceCacheCapacity, DefaultNonceCacheTTL)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.IPv4Prefix == 0 {
		cfg.IPv4Prefix = 24
	}
	if cfg.IPv6Prefix == 0 {
		cfg.IPv6Prefix = 48
	}
	return &Verifier{cfg: cfg}
}

func (v *Verifier) VerifyDownload(ctx context.Context, raw string, req RequestContext) (DownloadClaims, error) {
	payload, err := v.verifiedPayload(ctx, raw, "token_verify")
	if err != nil {
		return DownloadClaims{}, err
	}
	var claims DownloadClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return DownloadClaims{}, ErrMalformed
	}
	if err := v.verifyBase(claims.BaseClaims, "download", req); err != nil {
		return DownloadClaims{}, err
	}
	if claims.Size != "" && claims.Size != "*" && !contains(v.cfg.AllowedDownloadSizes, claims.Size) {
		return DownloadClaims{}, ErrDisallowedSize
	}
	return claims, nil
}

func (v *Verifier) AllowsDownloadSize(size string) bool {
	return contains(v.cfg.AllowedDownloadSizes, size)
}

func (v *Verifier) VerifyJob(ctx context.Context, raw string, req RequestContext) (JobClaims, error) {
	payload, err := v.verifiedPayload(ctx, raw, "token_verify")
	if err != nil {
		return JobClaims{}, err
	}
	var claims JobClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return JobClaims{}, ErrMalformed
	}
	if err := v.verifyBase(claims.BaseClaims, "job", req); err != nil {
		return JobClaims{}, err
	}
	if !contains(v.cfg.AllowedTools, claims.Tool) {
		return JobClaims{}, ErrDisallowedTool
	}
	if !v.cfg.NonceCache.Use(claims.Nonce, v.cfg.Now()) {
		return JobClaims{}, ErrReplay
	}
	return claims, nil
}

func (v *Verifier) verifiedPayload(ctx context.Context, raw, use string) ([]byte, error) {
	payload, signature, err := signing.SplitCompact(raw)
	if err != nil {
		return nil, ErrMalformed
	}
	var base BaseClaims
	if err := json.Unmarshal(payload, &base); err != nil {
		return nil, ErrMalformed
	}
	pub, err := v.publicKey(ctx, base.KID, use)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(pub, payload, signature) {
		return nil, ErrBadSignature
	}
	return payload, nil
}

func (v *Verifier) publicKey(ctx context.Context, kid, use string) (ed25519.PublicKey, error) {
	pub, err := v.cfg.Keyset.PublicKey(kid, use)
	if err == nil {
		return pub, nil
	}
	if !errors.Is(err, keyset.ErrUnknownKID) || v.cfg.Refresh == nil {
		if errors.Is(err, keyset.ErrUnknownKID) {
			return nil, ErrUnknownKID
		}
		return nil, err
	}
	keys, refreshErr := v.cfg.Refresh(ctx, kid)
	if refreshErr != nil {
		return nil, refreshErr
	}
	if addErr := v.cfg.Keyset.Add(keys); addErr != nil {
		return nil, addErr
	}
	pub, err = v.cfg.Keyset.PublicKey(kid, use)
	if err != nil {
		if errors.Is(err, keyset.ErrUnknownKID) {
			return nil, ErrUnknownKID
		}
		return nil, err
	}
	return pub, nil
}

func (v *Verifier) verifyBase(claims BaseClaims, wantType string, req RequestContext) error {
	if claims.Type != wantType {
		return ErrWrongType
	}
	if claims.Node != "" && claims.Node != req.NodeID && claims.Node != v.cfg.NodeID {
		return ErrWrongNode
	}
	if claims.ExpiresAt <= v.cfg.Now().Unix() {
		return ErrExpired
	}
	if len(claims.Nonce) < 16 {
		return ErrInvalidNonce
	}
	if !ipAllowed(claims.IPBinding, claims.IP, req.ClientIP, v.cfg.IPv4Prefix, v.cfg.IPv6Prefix) {
		return ErrIPBinding
	}
	return nil
}

func ipAllowed(policy, tokenIP, clientIP string, ipv4Prefix, ipv6Prefix int) bool {
	if policy == "" {
		policy = "relaxed"
	}
	if policy == "none" {
		return true
	}
	if tokenIP == "" || clientIP == "" {
		return false
	}
	if policy != "strict" && policy != "relaxed" {
		return false
	}
	// Normalize IPv4-mapped IPv6 (::ffff:192.0.2.1) to plain IPv4 on both sides
	// before comparing, so a token minted for an IPv4 address still matches a
	// peer the stack reported in mapped form (and vice versa). Strict equality
	// must use the normalized forms too, not the raw strings.
	tokenAddr, err := netip.ParseAddr(tokenIP)
	if err != nil {
		return false
	}
	clientAddr, err := netip.ParseAddr(clientIP)
	if err != nil {
		return false
	}
	tokenAddr = tokenAddr.Unmap()
	clientAddr = clientAddr.Unmap()
	if tokenAddr.Is4() != clientAddr.Is4() {
		return false
	}
	if policy == "strict" {
		return tokenAddr == clientAddr
	}
	bits := ipv6Prefix
	if tokenAddr.Is4() {
		bits = ipv4Prefix
	}
	prefix, err := tokenAddr.Prefix(bits)
	if err != nil {
		return false
	}
	return prefix.Contains(clientAddr)
}

func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}
