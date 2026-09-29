package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"hlg/internal/token"
)

type AdminVerifierConfig struct {
	NodeID     string
	PublicKeys map[string]ed25519.PublicKey
	NonceCache *token.NonceCache
	Now        func() time.Time
	Window     time.Duration
}

type AdminVerifier struct {
	cfg AdminVerifierConfig
}

const maxAdminBodyBytes = 1 << 20 // 1 MiB

func NewAdminVerifier(cfg AdminVerifierConfig) *AdminVerifier {
	if cfg.NonceCache == nil {
		cfg.NonceCache = token.NewNonceCache(token.DefaultNonceCacheCapacity, token.DefaultNonceCacheTTL)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Window == 0 {
		cfg.Window = 5 * time.Minute
	}
	return &AdminVerifier{cfg: cfg}
}

func (v *AdminVerifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxAdminBodyBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_body"})
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		if err := v.Verify(r, body); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (v *AdminVerifier) Verify(r *http.Request, body []byte) error {
	timestamp := r.Header.Get("x-lg-timestamp")
	nonce := r.Header.Get("x-lg-nonce")
	kid := r.Header.Get("x-lg-key-id")
	rawSignature := r.Header.Get("x-lg-signature")
	if timestamp == "" || nonce == "" || kid == "" || rawSignature == "" {
		return fmt.Errorf("missing admin signature")
	}
	issued, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("bad admin timestamp")
	}
	now := v.cfg.Now()
	if issued < now.Add(-v.cfg.Window).Unix() || issued > now.Add(v.cfg.Window).Unix() {
		return fmt.Errorf("admin timestamp outside window")
	}
	pub, ok := v.cfg.PublicKeys[kid]
	if !ok {
		return token.ErrUnknownKID
	}
	signature, err := base64.RawURLEncoding.DecodeString(rawSignature)
	if err != nil {
		return token.ErrBadSignature
	}
	bodyHash := sha256.Sum256(body)
	// The signature binds the request path only. Binding the query was tried
	// and reverted: the agent's single-use nonce cache already blocks replays
	// and TLS protects the query in transit, so query binding was only
	// defense-in-depth while forcing a deploy-order constraint (an un-updated
	// agent would reject iperf event streams). A failed signature is rejected
	// unconditionally.
	input := v.signatureInput(r, r.URL.Path, timestamp, nonce, bodyHash)
	if !ed25519.Verify(pub, []byte(input), signature) {
		return token.ErrBadSignature
	}
	// Consume the nonce only after the signature has authenticated the
	// request. Otherwise an attacker can evict/poison valid nonces with
	// unauthenticated traffic.
	if !v.cfg.NonceCache.Use(nonce, now) {
		return token.ErrReplay
	}
	return nil
}

func (v *AdminVerifier) signatureInput(r *http.Request, uri, timestamp, nonce string, bodyHash [sha256.Size]byte) string {
	return r.Method + "\n" + uri + "\n" + timestamp + "\n" + nonce + "\n" +
		fmt.Sprintf("%x", bodyHash[:]) + "\n" + v.cfg.NodeID
}
