package enroll

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"hlg/internal/atomicfile"
	"hlg/internal/config"
	"hlg/internal/runtime"
)

var ErrCertBundleNotFound = errors.New("cert bundle not found")

// startAnnounced ensures the agent_started marker is sent at most once per
// process, on the first successful-path config pull.
var startAnnounced atomic.Bool

type Request struct {
	EnrollToken              string   `json:"enroll_token"`
	AgentPublicKey           string   `json:"agent_public_key"`
	AgentEncryptionPublicKey string   `json:"agent_encryption_public_key"`
	DetectedIPv4             string   `json:"detected_ipv4,omitempty"`
	DetectedIPv6             string   `json:"detected_ipv6,omitempty"`
	Version                  string   `json:"version"`
	BuildID                  string   `json:"build_id,omitempty"`
	Capabilities             []string `json:"capabilities"`
}

type BootstrapRequest struct {
	AgentPublicKey           string   `json:"agent_public_key"`
	AgentEncryptionPublicKey string   `json:"agent_encryption_public_key"`
	DetectedIPv4             string   `json:"detected_ipv4,omitempty"`
	DetectedIPv6             string   `json:"detected_ipv6,omitempty"`
	Version                  string   `json:"version"`
	BuildID                  string   `json:"build_id,omitempty"`
	Capabilities             []string `json:"capabilities"`
}

type Response struct {
	Status string              `json:"status"`
	NodeID string              `json:"node_id"`
	Config config.SignedBundle `json:"config"`
}

type BootstrapResponse struct {
	Status    string              `json:"status"`
	NodeID    string              `json:"node_id"`
	NodeToken string              `json:"node_token"`
	Config    config.SignedBundle `json:"config"`
}

type Client struct {
	cfg        config.Config
	httpClient *http.Client
}

func NewClient(cfg config.Config) *Client {
	return &Client{cfg: cfg, httpClient: &http.Client{
		Timeout: 15 * time.Second,
		// Do not follow redirects. The controller URL is the trust anchor for
		// the TLS connection (self-signed on first contact); following a
		// redirect would let a hijacked/DNS-poisoned controller move the agent
		// to a third-party host for enrollment and config. A 3xx becomes a
		// hard failure so the retry loop keeps targeting the configured origin.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("controller redirect refused")
		},
	}}
}

func (c *Client) EnrollOnce(ctx context.Context) (Response, error) {
	if c.cfg.Controller == "" || c.cfg.EnrollToken == "" {
		return Response{}, fmt.Errorf("controller and enroll token are required")
	}
	identity, err := loadOrCreateIdentity(c.cfg.DataDir)
	if err != nil {
		return Response{}, err
	}
	reqBody := Request{
		EnrollToken:              c.cfg.EnrollToken,
		AgentPublicKey:           identity.PublicKey,
		AgentEncryptionPublicKey: identity.EncryptionPublicKey,
		DetectedIPv4:             c.cfg.PublicIPv4,
		DetectedIPv6:             c.cfg.PublicIPv6,
		Version:                  runtime.Version,
		BuildID:                  runtime.BuildID,
		Capabilities:             runtime.Capabilities,
	}
	encoded, err := json.Marshal(reqBody)
	if err != nil {
		return Response{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.Controller+"/_lg/enroll", bytes.NewReader(encoded))
	if err != nil {
		return Response{}, err
	}
	httpReq.Header.Set("content-type", "application/json")
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return Response{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return Response{}, fmt.Errorf("enroll failed: %s", resp.Status)
	}
	var out Response
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Response{}, err
	}
	if out.Status == "active" {
		if err := c.StoreConfig(out.Config); err != nil {
			return Response{}, err
		}
	}
	return out, nil
}

func (c *Client) BootstrapOnce(ctx context.Context) (BootstrapResponse, error) {
	if c.cfg.Controller == "" || c.cfg.InitToken == "" {
		return BootstrapResponse{}, fmt.Errorf("controller and init token are required")
	}
	identity, err := loadOrCreateIdentity(c.cfg.DataDir)
	if err != nil {
		return BootstrapResponse{}, err
	}
	reqBody := BootstrapRequest{
		AgentPublicKey:           identity.PublicKey,
		AgentEncryptionPublicKey: identity.EncryptionPublicKey,
		DetectedIPv4:             c.cfg.PublicIPv4,
		DetectedIPv6:             c.cfg.PublicIPv6,
		Version:                  runtime.Version,
		BuildID:                  runtime.BuildID,
		Capabilities:             runtime.Capabilities,
	}
	encoded, err := json.Marshal(reqBody)
	if err != nil {
		return BootstrapResponse{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.Controller+"/_lg/control/config", bytes.NewReader(encoded))
	if err != nil {
		return BootstrapResponse{}, err
	}
	httpReq.Header.Set("authorization", "Bearer "+c.cfg.InitToken)
	httpReq.Header.Set("content-type", "application/json")
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return BootstrapResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return BootstrapResponse{}, fmt.Errorf("bootstrap failed: %s", resp.Status)
	}
	var out BootstrapResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return BootstrapResponse{}, err
	}
	if out.NodeToken == "" {
		return BootstrapResponse{}, fmt.Errorf("bootstrap response missing node token")
	}
	if err := c.StoreNodeToken(out.NodeToken); err != nil {
		return BootstrapResponse{}, err
	}
	if err := c.StoreConfig(out.Config); err != nil {
		return BootstrapResponse{}, err
	}
	return out, nil
}

func (c *Client) PullConfig(ctx context.Context) (config.SignedBundle, error) {
	if c.cfg.Controller == "" || c.cfg.NodeToken == "" || c.cfg.NodeID == "" {
		return config.SignedBundle{}, fmt.Errorf("controller, node token, and node id are required")
	}
	params := url.Values{}
	params.Set("node", c.cfg.NodeID)
	if c.cfg.PublicIPv4 != "" {
		params.Set("detected_ipv4", c.cfg.PublicIPv4)
	}
	if c.cfg.PublicIPv6 != "" {
		params.Set("detected_ipv6", c.cfg.PublicIPv6)
	}
	params.Set("version", runtime.Version)
	if runtime.BuildID != "" && runtime.BuildID != "unknown" {
		params.Set("build_id", runtime.BuildID)
	}
	// Report the config revision this agent is currently serving so the
	// controller can tell whether it has picked up the latest config (the
	// config analogue of cert_bundle_id acknowledgement). Stored at
	// config.json by StoreConfig.
	if applied := storedConfigVersion(c.cfg.DataDir); applied > 0 {
		params.Set("config_version", strconv.FormatInt(applied, 10))
	}
	// Announce process start exactly once per process, on the first pull.
	if startAnnounced.CompareAndSwap(false, true) {
		params.Set("started", "1")
	}
	endpoint := c.cfg.Controller + "/_lg/control/config?" + params.Encode()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return config.SignedBundle{}, err
	}
	httpReq.Header.Set("authorization", "Bearer "+c.cfg.NodeToken)
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return config.SignedBundle{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return config.SignedBundle{}, fmt.Errorf("config pull failed: %s", resp.Status)
	}
	var out config.SignedBundle
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return config.SignedBundle{}, err
	}
	if err := c.StoreConfig(out); err != nil {
		return config.SignedBundle{}, err
	}
	return out, nil
}

func (c *Client) PullCertBundle(ctx context.Context) (config.CertificateBundle, error) {
	if c.cfg.Controller == "" || c.cfg.NodeToken == "" || c.cfg.NodeID == "" {
		return config.CertificateBundle{}, fmt.Errorf("controller, node token, and node id are required")
	}
	endpoint := c.cfg.Controller + "/_lg/control/cert-bundle?node=" + url.QueryEscape(c.cfg.NodeID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return config.CertificateBundle{}, err
	}
	httpReq.Header.Set("authorization", "Bearer "+c.cfg.NodeToken)
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return config.CertificateBundle{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return config.CertificateBundle{}, ErrCertBundleNotFound
	}
	if resp.StatusCode >= 300 {
		return config.CertificateBundle{}, fmt.Errorf("cert bundle pull failed: %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return config.CertificateBundle{}, err
	}
	out, err := c.decodeCertificateBundle(body)
	if err != nil {
		return config.CertificateBundle{}, err
	}
	// The controller keeps the row pending until this node confirms it applied
	// the bundle, so remember which row to acknowledge once ApplyBundle succeeds.
	out.NodeBundleID = resp.Header.Get("x-lg-node-bundle-id")
	return out, nil
}

// AckCertBundle tells the controller whether the bundle was applied. A failed
// apply is reported so the controller logs it and keeps the row retryable.
func (c *Client) AckCertBundle(ctx context.Context, nodeBundleID string, applyErr error) error {
	if nodeBundleID == "" || c.cfg.Controller == "" || c.cfg.NodeToken == "" {
		return nil
	}
	body := map[string]any{"node_bundle_id": nodeBundleID, "status": "applied"}
	if applyErr != nil {
		body["status"] = "failed"
		body["error"] = applyErr.Error()
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	endpoint := c.cfg.Controller + "/_lg/control/cert/ack"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	httpReq.Header.Set("authorization", "Bearer "+c.cfg.NodeToken)
	httpReq.Header.Set("content-type", "application/json")
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("cert ack failed: %s", resp.Status)
	}
	return nil
}

func (c *Client) decodeCertificateBundle(body []byte) (config.CertificateBundle, error) {
	// Only the encrypted envelope is accepted. The response arrives over TLS
	// from the controller, but the controller's certificate is self-signed
	// until a managed bundle lands, so a plaintext fallback let anyone able to
	// terminate that connection inject a bundle that skips ECDH entirely. The
	// envelope binds the payload to this agent's encryption key.
	var envelope certificateEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return config.CertificateBundle{}, fmt.Errorf("certificate bundle is not an encrypted envelope: %w", err)
	}
	if envelope.Alg != "ECDH-P256+A256GCM" {
		return config.CertificateBundle{}, fmt.Errorf("unsupported certificate envelope: %s", envelope.Alg)
	}
	identity, err := loadOrCreateIdentity(c.cfg.DataDir)
	if err != nil {
		return config.CertificateBundle{}, err
	}
	privateBytes, err := base64.RawURLEncoding.DecodeString(identity.EncryptionPrivateKey)
	if err != nil {
		return config.CertificateBundle{}, err
	}
	ephemeralBytes, err := base64.RawURLEncoding.DecodeString(envelope.EPK)
	if err != nil {
		return config.CertificateBundle{}, err
	}
	iv, err := base64.RawURLEncoding.DecodeString(envelope.IV)
	if err != nil {
		return config.CertificateBundle{}, err
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return config.CertificateBundle{}, err
	}
	priv, err := ecdh.P256().NewPrivateKey(privateBytes)
	if err != nil {
		return config.CertificateBundle{}, err
	}
	ephemeral, err := ecdh.P256().NewPublicKey(ephemeralBytes)
	if err != nil {
		return config.CertificateBundle{}, err
	}
	shared, err := priv.ECDH(ephemeral)
	if err != nil {
		return config.CertificateBundle{}, err
	}
	keyBytes := sha256.Sum256(shared)
	block, err := aes.NewCipher(keyBytes[:])
	if err != nil {
		return config.CertificateBundle{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return config.CertificateBundle{}, err
	}
	plaintext, err := aead.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return config.CertificateBundle{}, err
	}
	var out config.CertificateBundle
	if err := json.Unmarshal(plaintext, &out); err != nil {
		return config.CertificateBundle{}, err
	}
	return out, nil
}

type certificateEnvelope struct {
	Alg        string `json:"alg"`
	EPK        string `json:"epk"`
	IV         string `json:"iv"`
	Ciphertext string `json:"ciphertext"`
}

func (c *Client) StoreConfig(bundle config.SignedBundle) error {
	if err := os.MkdirAll(c.cfg.DataDir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(filepath.Join(c.cfg.DataDir, "config.json"), b, 0o600)
}

func (c *Client) StoreNodeToken(token string) error {
	if err := os.MkdirAll(c.cfg.DataDir, 0o700); err != nil {
		return err
	}
	return atomicfile.Write(filepath.Join(c.cfg.DataDir, "node-token"), []byte(token+"\n"), 0o600)
}

func LoadNodeToken(dataDir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dataDir, "node-token"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func LoadBootstrap(dataDir string) (BootstrapResponse, error) {
	b, err := os.ReadFile(filepath.Join(dataDir, "bootstrap.json"))
	if err != nil {
		return BootstrapResponse{}, err
	}
	var out BootstrapResponse
	if err := json.Unmarshal(b, &out); err != nil {
		return BootstrapResponse{}, err
	}
	if out.NodeToken == "" {
		return BootstrapResponse{}, fmt.Errorf("bootstrap file missing node token")
	}
	return out, nil
}

func LoadStoredConfig(dataDir string) (config.SignedBundle, error) {
	b, err := os.ReadFile(filepath.Join(dataDir, "config.json"))
	if err != nil {
		return config.SignedBundle{}, err
	}
	var out config.SignedBundle
	if err := json.Unmarshal(b, &out); err != nil {
		return config.SignedBundle{}, err
	}
	return out, nil
}

// storedConfigVersion is the version of the most recently stored signed config
// bundle, or 0 when none is stored yet. It is what the agent reports back as
// the config revision it is serving.
func storedConfigVersion(dataDir string) int64 {
	stored, err := LoadStoredConfig(dataDir)
	if err != nil {
		return 0
	}
	return stored.Version
}
