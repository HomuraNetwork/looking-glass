// Package agentupdate implements `hlg-agent update`: fetch the controller's
// current agent release, verify it, and replace this binary in place.
//
// Security model:
//   - The controller signs a release descriptor with its config signing key
//     over a canonical newline-joined payload (see SigningInput).
//   - This agent verifies that signature with the `config_verify` public key
//     from its stored signed config bundle, so a tampered or stale response
//     cannot point the node at an arbitrary binary.
//   - The downloaded bytes must match the signed SHA-256 and size before the
//     running binary is touched; a mismatch aborts with the old binary intact.
//   - Replacement is atomic (temp file in the same directory, then rename),
//     keeps a .bak, and rolls back if the service fails to restart.
package agentupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"hlg/internal/config"
	"hlg/internal/keyset"
)

var (
	ErrDescriptorSignature = errors.New("release signature invalid")
	ErrDescriptorNode      = errors.New("release node mismatch")
	ErrDescriptorExpired   = errors.New("release descriptor expired")
	ErrDescriptorConfigKey = errors.New("release config_verify key missing")
	ErrDownloadDigest      = errors.New("downloaded agent binary failed digest check")
	ErrDownloadSize        = errors.New("downloaded agent binary size mismatch")
)

// Descriptor is the controller's signed description of the current agent
// release for one target. Field names match the worker's JSON exactly.
type Descriptor struct {
	BuildID   string `json:"build_id"`
	Target    string `json:"target"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	Path      string `json:"path"`
	NodeID    string `json:"node_id"`
	ExpiresAt int64  `json:"expires_at"`
	ConfigKID string `json:"config_kid"`
	Signature string `json:"signature"`
	// SigningInput is the controller's own rendering of the signed payload; it
	// is re-derived locally and only used as a cross-check.
	SigningInput string `json:"signing_input"`
}

// signingInputSkew tolerates clock drift between the node and the controller.
const signingInputSkew = 5 * time.Minute

// SigningInput is the exact byte sequence covered by the release signature. It
// must stay byte-identical to the worker's agentReleaseSigningInput.
func SigningInput(d Descriptor) string {
	return "hlg-agent-release\n" +
		d.BuildID + "\n" +
		d.Target + "\n" +
		d.SHA256 + "\n" +
		strconv.FormatInt(d.Size, 10) + "\n" +
		d.Path + "\n" +
		d.NodeID + "\n" +
		strconv.FormatInt(d.ExpiresAt, 10)
}

// VerifyDescriptor checks a descriptor against the expected node, the current
// time, and the trusted config_verify public key. It is pure so it can be
// tested without a controller.
func VerifyDescriptor(d Descriptor, nodeID string, now time.Time, configKey ed25519.PublicKey) error {
	if nodeID == "" || d.NodeID != nodeID {
		return ErrDescriptorNode
	}
	if d.ExpiresAt <= now.Add(-signingInputSkew).Unix() {
		return ErrDescriptorExpired
	}
	if d.BuildID == "" || d.Target == "" || d.SHA256 == "" || d.Size <= 0 || d.Path == "" {
		return ErrDescriptorSignature
	}
	if configKey == nil {
		return ErrDescriptorConfigKey
	}
	// Re-derive the payload rather than trusting the server's copy; the
	// signature must cover exactly these bytes.
	input := SigningInput(d)
	if d.SigningInput != "" && d.SigningInput != input {
		return ErrDescriptorSignature
	}
	signature, err := base64.RawURLEncoding.DecodeString(d.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return ErrDescriptorSignature
	}
	if !ed25519.Verify(configKey, []byte(input), signature) {
		return ErrDescriptorSignature
	}
	return nil
}

// ConfigVerifyKey extracts the config_verify key named by the descriptor from a
// signed config bundle's keyset.
func ConfigVerifyKey(bundle config.SignedBundle, kid string) (ed25519.PublicKey, error) {
	ks, err := keyset.New(bundle.Keyset)
	if err != nil {
		return nil, err
	}
	key, err := ks.PublicKey(kid, "config_verify")
	if err != nil {
		return nil, ErrDescriptorConfigKey
	}
	return key, nil
}

// Options configures a Run. The zero value is not usable: Controller, NodeToken
// and binary locations are required.
type Options struct {
	Controller     string
	NodeToken      string
	NodeID         string
	DataDir        string
	InstallDir     string
	BinaryName     string
	ServiceName    string
	ServiceMode    string // systemd | init.d | none
	Arch           string
	CurrentBuildID string

	// Client performs the descriptor + binary requests. When nil a client that
	// refuses redirects is used.
	Client *http.Client

	// Restart restarts the agent service after a successful replace. When nil
	// the binary is replaced but no restart happens (the caller must handle it).
	Restart func() error
	// ApplyCaps applies file capabilities to the new binary. Best-effort.
	ApplyCaps func(path string) error

	// Check stops after verification and reports whether an update is due.
	Check bool
	// Force reinstalls even when the build id already matches.
	Force bool

	Logf func(format string, args ...any)
}

// Result reports what Run did.
type Result struct {
	CurrentBuildID string
	ReleaseBuildID string
	ReleaseSHA256  string
	UpToDate       bool
	Updated        bool
}

// Run fetches, verifies and (unless Check) installs the current release.
func Run(ctx context.Context, opts Options) (Result, error) {
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	client := opts.Client
	if client == nil {
		client = &http.Client{
			Timeout: 10 * time.Minute,
			// Never follow redirects: the controller origin is the trust anchor
			// and the signed descriptor already names the download path.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return fmt.Errorf("controller redirect refused")
			},
		}
	}

	bundle, err := loadVerifiedBundle(opts.DataDir, opts.NodeID)
	if err != nil {
		return Result{}, err
	}

	descriptor, err := fetchDescriptor(ctx, client, opts)
	if err != nil {
		return Result{}, err
	}
	// The descriptor names the config key that signed it; fall back to the
	// bundle's own config_kid when an older controller omits it.
	configKID := descriptor.ConfigKID
	if configKID == "" {
		configKID = bundle.ConfigKID
	}
	configKey, err := ConfigVerifyKey(bundle, configKID)
	if err != nil {
		return Result{}, err
	}
	if err := VerifyDescriptor(descriptor, opts.NodeID, time.Now(), configKey); err != nil {
		return Result{}, err
	}

	result := Result{CurrentBuildID: opts.CurrentBuildID, ReleaseBuildID: descriptor.BuildID, ReleaseSHA256: descriptor.SHA256}
	if !opts.Force && opts.CurrentBuildID != "" && opts.CurrentBuildID != "unknown" && opts.CurrentBuildID == descriptor.BuildID {
		result.UpToDate = true
		logf("already on build %s", descriptor.BuildID)
		return result, nil
	}
	if opts.Check {
		logf("update available: %s -> %s", opts.CurrentBuildID, descriptor.BuildID)
		return result, nil
	}

	binaryPath := filepath.Join(opts.InstallDir, opts.BinaryName)
	tempPath := filepath.Join(opts.InstallDir, "."+opts.BinaryName+".new")
	downloaded, err := downloadBinary(ctx, client, opts, descriptor, tempPath)
	if err != nil {
		return result, err
	}
	defer os.Remove(downloaded) // no-op once renamed into place

	if err := installBinary(downloaded, binaryPath, opts.ApplyCaps); err != nil {
		return result, err
	}
	logf("installed build %s at %s", descriptor.BuildID, binaryPath)

	result.Updated = true
	if opts.Restart == nil {
		logf("no service restart requested; restart the agent to run the new build")
		return result, nil
	}
	if err := opts.Restart(); err != nil {
		logf("service restart failed (%v); rolling back to previous binary", err)
		if rollbackErr := rollbackBinary(binaryPath); rollbackErr != nil {
			return result, fmt.Errorf("restart failed: %w (rollback also failed: %v)", err, rollbackErr)
		}
		result.Updated = false
		if restartErr := opts.Restart(); restartErr != nil {
			return result, fmt.Errorf("restart failed and rollback restart failed: %w", restartErr)
		}
		return result, fmt.Errorf("restart failed, rolled back: %w", err)
	}
	// The new binary is running; the backup is no longer needed for recovery.
	_ = os.Remove(binaryPath + ".bak")
	return result, nil
}

func loadVerifiedBundle(dataDir, nodeID string) (config.SignedBundle, error) {
	body, err := os.ReadFile(filepath.Join(dataDir, "config.json"))
	if err != nil {
		return config.SignedBundle{}, fmt.Errorf("load stored config: %w", err)
	}
	var bundle config.SignedBundle
	if err := json.Unmarshal(body, &bundle); err != nil {
		return config.SignedBundle{}, fmt.Errorf("parse stored config: %w", err)
	}
	// Only trust keys carried by a validly-signed, unexpired bundle: a locally
	// tampered config.json would otherwise let an attacker supply their own
	// release-signing key.
	verifyNodeID := nodeID
	if verifyNodeID == "" {
		verifyNodeID = bundle.NodeID
	}
	if err := config.VerifySignedBundle(bundle, verifyNodeID, time.Now()); err != nil {
		return config.SignedBundle{}, fmt.Errorf("stored config is not trusted: %w", err)
	}
	return bundle, nil
}

func fetchDescriptor(ctx context.Context, client *http.Client, opts Options) (Descriptor, error) {
	endpoint := opts.Controller + "/_agent/update?arch=" + opts.Arch
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Descriptor{}, err
	}
	req.Header.Set("authorization", "Bearer "+opts.NodeToken)
	resp, err := client.Do(req)
	if err != nil {
		return Descriptor{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return Descriptor{}, fmt.Errorf("release lookup failed: %s: %s", resp.Status, string(detail))
	}
	var descriptor Descriptor
	if err := json.NewDecoder(resp.Body).Decode(&descriptor); err != nil {
		return Descriptor{}, fmt.Errorf("decode release descriptor: %w", err)
	}
	return descriptor, nil
}

// downloadBinary streams the release to tempPath, enforcing the signed size and
// SHA-256. The file is only returned on success; partial or mismatched
// downloads are removed.
func downloadBinary(ctx context.Context, client *http.Client, opts Options, d Descriptor, tempPath string) (string, error) {
	url := d.Path
	if url == "" {
		url = "/_agent/binary/" + d.Target
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, opts.Controller+url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("authorization", "Bearer "+opts.NodeToken)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("binary download failed: %s", resp.Status)
	}

	if err := os.MkdirAll(opts.InstallDir, 0o755); err != nil {
		return "", err
	}
	file, err := os.OpenFile(tempPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return "", err
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, hasher), io.LimitReader(resp.Body, d.Size+1))
	closeErr := file.Close()
	if copyErr != nil {
		os.Remove(tempPath)
		return "", copyErr
	}
	if closeErr != nil {
		os.Remove(tempPath)
		return "", closeErr
	}
	if written != d.Size {
		os.Remove(tempPath)
		return "", fmt.Errorf("%w: got %d, want %d", ErrDownloadSize, written, d.Size)
	}
	if got := hex.EncodeToString(hasher.Sum(nil)); got != d.SHA256 {
		os.Remove(tempPath)
		return "", fmt.Errorf("%w: got %s, want %s", ErrDownloadDigest, got, d.SHA256)
	}
	return tempPath, nil
}

// installBinary atomically replaces binaryPath with downloaded, keeping the
// previous binary at binaryPath+".bak" for manual recovery.
func installBinary(downloaded, binaryPath string, applyCaps func(string) error) error {
	backupPath := binaryPath + ".bak"
	hadPrevious := false
	if _, err := os.Stat(binaryPath); err == nil {
		hadPrevious = true
		// Replace any stale backup so the rename below cannot fail on an
		// existing .bak from an earlier run.
		_ = os.Remove(backupPath)
		if err := os.Rename(binaryPath, backupPath); err != nil {
			return fmt.Errorf("back up current binary: %w", err)
		}
	}
	if err := os.Rename(downloaded, binaryPath); err != nil {
		if hadPrevious {
			_ = os.Rename(backupPath, binaryPath)
		}
		return fmt.Errorf("install new binary: %w", err)
	}
	if applyCaps != nil {
		if err := applyCaps(binaryPath); err != nil {
			// Capabilities are optional when the service manager grants them via
			// AmbientCapabilities; a failure here must not undo a good binary.
			log.Printf("agent update: warning: setting file capabilities failed: %v", err)
		}
	}
	return nil
}

func rollbackBinary(binaryPath string) error {
	backupPath := binaryPath + ".bak"
	if _, err := os.Stat(backupPath); err != nil {
		return fmt.Errorf("no backup to roll back to: %w", err)
	}
	return os.Rename(backupPath, binaryPath)
}
