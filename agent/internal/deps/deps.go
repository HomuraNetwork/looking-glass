// Package deps manages the agent's runtime tools.
//
// Single-file binaries (nexttrace) are installed under <data-dir>/deps.
// Ping, traceroute, and mtr have built-in implementations
// when no system binary is selected. Other OS packages use the detected manager.
package deps

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Kind selects how a tool is installed.
type Kind int

const (
	// KindBinary is a single-file binary downloaded into <data-dir>/deps.
	KindBinary Kind = iota
	// KindPackage is an OS package installed through the system package manager.
	KindPackage
)

// PackageManagers maps a manager family to the tool's package name in it.
type PackageManagers map[string]string

// Tool describes one managed dependency.
type Tool struct {
	Name string
	Kind Kind
	// Packages names the tool's package per manager family (apt, dnf, yum, apk).
	// Empty means the tool has no package for that family.
	Packages PackageManagers
	Caps     []string // file capabilities applied after install
	// Paths lists the binaries to setcap for KindPackage (KindBinary uses its
	// installed path). Resolved through symlinks before setcap.
	Paths []string
	// Dist is the controller-served verified fallback asset name.
	Dist string
	// Upstream means the binary is fetched from its official release.
	Upstream bool
	// UpstreamFile is the upstream asset name template ({arch}).
	UpstreamFile string
}

// PackageManager returns the detected family ("apt", "dnf", "yum", "apk") and
// its install command, or an empty family when none is supported.
func PackageManager() string {
	for _, pm := range []struct {
		family  string
		command string
	}{
		{"apt", "apt-get"},
		{"dnf", "dnf"},
		{"yum", "yum"},
		{"apk", "apk"},
	} {
		if _, err := exec.LookPath(pm.command); err == nil {
			return pm.family
		}
	}
	return ""
}

func pm(names ...string) PackageManagers {
	m := PackageManagers{}
	for _, n := range names {
		family, name, ok := strings.Cut(n, ":")
		if ok {
			m[family] = name
		}
	}
	return m
}

var registry = map[string]Tool{
	"nexttrace":  {Name: "nexttrace", Kind: KindBinary, Caps: []string{"cap_net_raw", "cap_net_admin", "cap_net_bind_service"}, Upstream: true, UpstreamFile: "nexttrace_linux_{arch}"},
	"iperf3":     {Name: "iperf3", Kind: KindPackage, Packages: pm("apt:iperf3", "dnf:iperf3", "yum:iperf3", "apk:iperf3"), Dist: "hlg-iperf3-linux-{arch}"},
	"mtr":        {Name: "mtr", Kind: KindPackage, Packages: pm("apt:mtr-tiny", "dnf:mtr", "yum:mtr", "apk:mtr"), Caps: []string{"cap_net_raw"}, Paths: []string{"/usr/bin/mtr", "/usr/bin/mtr-packet"}},
	"traceroute": {Name: "traceroute", Kind: KindPackage, Packages: pm("apt:traceroute", "dnf:traceroute", "yum:traceroute", "apk:traceroute"), Caps: []string{"cap_net_raw"}, Paths: []string{"/usr/bin/traceroute"}},
	"ping":       {Name: "ping", Kind: KindPackage, Packages: pm("apt:iputils-ping", "dnf:iputils", "yum:iputils", "apk:iputils"), Caps: []string{"cap_net_raw"}, Paths: []string{"/usr/bin/ping"}},
}

// Names returns the managed tool names, sorted.
func Names() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// All returns every managed tool, sorted by name.
func All() []Tool {
	names := Names()
	tools := make([]Tool, 0, len(names))
	for _, name := range names {
		tools = append(tools, registry[name])
	}
	return tools
}

// Lookup resolves a tool by name.
func Lookup(name string) (Tool, error) {
	tool, ok := registry[strings.TrimSpace(name)]
	if !ok {
		return Tool{}, fmt.Errorf("unknown dependency %q (known: %s)", name, strings.Join(Names(), ", "))
	}
	return tool, nil
}

// DepsDir is the directory holding agent-managed binaries.
func DepsDir(dataDir string) string {
	return filepath.Join(dataDir, "deps")
}

// BinaryPath is the path of an agent-managed binary.
func BinaryPath(dataDir, name string) string {
	return filepath.Join(DepsDir(dataDir), name)
}

// Check reports whether the tool is available (system PATH, then the
// agent-managed copy) with no respect for an explicit choice. Prefer Effective
// when the recorded tools map is available.
func Check(dataDir string, tool Tool) (bool, string) {
	if found, err := exec.LookPath(tool.Name); err == nil {
		return true, found
	}
	path := BinaryPath(dataDir, tool.Name)
	if info, err := os.Stat(path); err == nil {
		if info.Mode()&0o111 == 0 {
			return false, "installed but not executable"
		}
		return true, path
	}
	if IsBuiltin(tool.Name) {
		return true, BuiltinMarker
	}
	return false, "not found in PATH"
}

// Effective resolves the tool the runtime will actually run, honoring an
// explicit recorded choice:
//
//	tools[name] == BuiltinMarker -> built-in probe
//	tools[name] == ""            -> automatic (system, then data-dir, then built-in)
//	tools[name] == <path>        -> that exact path (system, download or custom)
//	absent                       -> automatic
//
// It returns false only when nothing usable is available.
func Effective(tools map[string]string, dataDir, name string) (bool, string) {
	recorded, has := tools[name]
	if has && recorded != "" {
		if recorded == BuiltinMarker {
			if IsBuiltin(name) {
				return true, BuiltinMarker
			}
			return false, "recorded built-in, but no built-in implementation"
		}
		if info, err := os.Stat(recorded); err == nil && info.Mode()&0o111 != 0 {
			return true, recorded
		}
		return false, fmt.Sprintf("recorded path %s is missing", recorded)
	}
	if _, ok := registry[name]; !ok {
		return false, "unknown tool"
	}
	// Automatic: a system binary wins, else an agent-managed copy, else built-in.
	if found, err := exec.LookPath(name); err == nil {
		return true, found
	}
	if info, err := os.Stat(BinaryPath(dataDir, name)); err == nil && info.Mode()&0o111 != 0 {
		return true, BinaryPath(dataDir, name)
	}
	if IsBuiltin(name) {
		return true, BuiltinMarker
	}
	return false, "not found"
}

// IsBuiltin reports whether the Go agent implements the runtime probe.
func IsBuiltin(name string) bool {
	switch name {
	case "ping", "traceroute", "mtr":
		return true
	default:
		return false
	}
}

// Install installs (or, with force, reinstalls) the tool. It requires root for
// packages and for setting capabilities on binary installs.
func Install(ctx context.Context, controller, dataDir string, tool Tool, force bool, logf func(string, ...any)) error {
	if tool.Kind == KindBinary {
		return installBinary(ctx, controller, dataDir, tool, force, logf)
	}
	if err := installPackage(tool, force, logf); err != nil {
		if tool.Dist == "" {
			return err
		}
		logf("deps: %s package unavailable (%v); trying verified controller binary", tool.Name, err)
		return installBinary(ctx, controller, dataDir, tool, force, logf)
	}
	return nil
}

func installPackage(tool Tool, force bool, logf func(string, ...any)) error {
	family := PackageManager()
	pkg := tool.Packages[family]
	if family == "" || pkg == "" {
		return fmt.Errorf("%s has no package for the detected package manager (%s)", tool.Name, orNone(family))
	}
	logf("deps: %s install %s", family, pkg)
	if err := packageInstall(family, pkg, force); err != nil {
		return err
	}
	return applyCaps(tool.Caps, tool.Paths...)
}

// Upgrade upgrades the tool if a newer version is available, returning whether
// anything changed. It first checks whether an update is actually needed so a
// no-op run reports "already up to date".
func Upgrade(ctx context.Context, controller, dataDir string, tool Tool, logf func(string, ...any)) (bool, error) {
	needed, detail := updateAvailable(ctx, controller, dataDir, tool)
	if !needed {
		logf("deps: %s: already up to date%s", tool.Name, detail)
		return false, nil
	}
	logf("deps: %s: update available%s", tool.Name, detail)
	if tool.Kind == KindBinary {
		return true, installBinary(ctx, controller, dataDir, tool, true, logf)
	}
	if tool.Dist != "" && !hasSystemBinary(dataDir, tool.Name) {
		return true, installBinary(ctx, controller, dataDir, tool, true, logf)
	}
	family := PackageManager()
	pkg := tool.Packages[family]
	if family == "" || pkg == "" {
		return false, fmt.Errorf("%s has no package for the detected package manager (%s)", tool.Name, orNone(family))
	}
	logf("deps: %s upgrade %s", family, pkg)
	if err := packageUpgrade(family, pkg); err != nil {
		return false, err
	}
	return true, applyCaps(tool.Caps, tool.Paths...)
}

// UpgradeManaged updates only the agent-owned binary in data/deps. Callers
// choose this path after confirming it is the runtime's effective source, so
// the presence of a system package must not redirect the upgrade to apt/apk.
func UpgradeManaged(ctx context.Context, controller, dataDir string, tool Tool, logf func(string, ...any)) (bool, error) {
	if !tool.Upstream && tool.Dist == "" {
		return false, fmt.Errorf("%s has no managed binary", tool.Name)
	}
	needed, detail := updateAvailable(ctx, controller, dataDir, tool)
	if !needed {
		logf("deps: %s: already up to date%s", tool.Name, detail)
		return false, nil
	}
	logf("deps: %s: update available%s", tool.Name, detail)
	return true, installBinary(ctx, controller, dataDir, tool, true, logf)
}

// updateAvailable reports whether an update is needed and a short reason.
func updateAvailable(ctx context.Context, controller, dataDir string, tool Tool) (bool, string) {
	// Agent-managed download: compare the local file against the controller's
	// published SHA-256 for this architecture.
	if tool.Dist != "" {
		path := BinaryPath(dataDir, tool.Name)
		if info, err := os.Stat(path); err == nil && info.Mode()&0o111 != 0 {
			arch, archErr := runtimeArch()
			if archErr == nil {
				fileName := strings.ReplaceAll(tool.Dist, "{arch}", arch)
				if expected, err := fetchExpectedSHA256(ctx, controller, fileName); err == nil {
					if local, err := fileSHA256(path); err == nil {
						if local == expected {
							return false, " (sha256 matches)"
						}
						return true, " (sha256 differs)"
					}
				}
			}
		}
		return true, ""
	}
	// Compare upstream binaries with the current digest published by the
	// controller from GitHub release metadata.
	if tool.Upstream {
		if arch, err := runtimeArch(); err == nil {
			fileName := strings.ReplaceAll(tool.UpstreamFile, "{arch}", arch)
			if asset, err := fetchUpstreamAsset(ctx, controller, tool.Name, arch, fileName); err == nil {
				if actual, err := fileSHA256(BinaryPath(dataDir, tool.Name)); err == nil && actual == asset.SHA256 {
					if entry, ok := readManifest(dataDir).Binaries[tool.Name]; ok && entry.Origin == asset.URL {
						return false, " (controller-published sha256 matches)"
					}
				}
			}
		}
		return true, ""
	}
	// Package-managed tool (ping/mtr/traceroute/iperf3-as-package/curl): the
	// system manager owns the version; upgrade directly.
	return true, ""
}

func orNone(value string) string {
	if value == "" {
		return "none"
	}
	return value
}

// HasStandaloneBuild reports whether a verified controller fallback or upstream download exists.
func HasStandaloneBuild(name string) bool {
	tool, ok := registry[name]
	return ok && (tool.Upstream || tool.Dist != "")
}

// SystemPath returns the PATH location of the tool's executable, or "".
func SystemPath(name string) string {
	if path, err := exec.LookPath(name); err == nil {
		return path
	}
	return ""
}

// HasPackage reports whether the detected package manager can install this tool.
func HasPackage(tool Tool) bool {
	family := PackageManager()
	return family != "" && tool.Packages[family] != ""
}

// hasSystemBinary reports whether a non-agent-managed copy exists on PATH.
func hasSystemBinary(dataDir, name string) bool {
	path := SystemPath(name)
	return path != "" && path != BinaryPath(dataDir, name)
}

// UpdateCheck reports whether a downloaded tool's local binary matches the
// controller's published SHA-256 (for iperf3). Returns (known, matches): known
// is false when the tool is not controller-served or the manifest is
// unreachable, in which case callers should not report a mismatch.
func UpdateCheck(ctx context.Context, controller, dataDir string, tool Tool) (bool, bool) {
	if tool.Dist == "" || controller == "" {
		return false, false
	}
	path := BinaryPath(dataDir, tool.Name)
	if _, err := os.Stat(path); err != nil {
		return false, false
	}
	arch, err := runtimeArch()
	if err != nil {
		return false, false
	}
	fileName := strings.ReplaceAll(tool.Dist, "{arch}", arch)
	expected, err := fetchExpectedSHA256(ctx, controller, fileName)
	if err != nil || expected == "" {
		return false, false
	}
	local, err := fileSHA256(path)
	if err != nil {
		return false, false
	}
	return true, strings.EqualFold(local, expected)
}

// ReadManifestEntry returns the recorded manifest entry for a downloaded tool.
func ReadManifestEntry(dataDir, name string) (ManifestEntry, bool) {
	entry, ok := readManifest(dataDir).Binaries[name]
	return entry, ok
}

// CheckManagedSHA512 compares an agent-managed binary with the digest recorded
// when it was installed. managed is false when the tool has no recorded
// managed binary; a missing or unreadable binary is returned as an error.
func CheckManagedSHA512(dataDir, name string) (expected, actual string, managed bool, err error) {
	entry, ok := ReadManifestEntry(dataDir, name)
	if !ok || entry.SHA512 == "" {
		return "", "", false, nil
	}
	actual, err = fileSHA512(BinaryPath(dataDir, name))
	return entry.SHA512, actual, true, err
}

func InstallDownloaded(ctx context.Context, controller, dataDir string, tool Tool, force bool, logf func(string, ...any)) (string, error) {
	if !HasStandaloneBuild(tool.Name) {
		return "", fmt.Errorf("%s has no standalone build", tool.Name)
	}
	if err := installBinary(ctx, controller, dataDir, tool, force, logf); err != nil {
		return "", err
	}
	return BinaryPath(dataDir, tool.Name), nil
}

// BuiltinMarker is a tools-map value meaning "use the built-in engine".
const BuiltinMarker = "builtin"

// UsablePath returns the recorded binary path for a tool, or "" when it is unset
// or marked as a built-in engine (neither has a filesystem binary).
func UsablePath(tools map[string]string, name string) string {
	path := tools[name]
	if path == "" || path == BuiltinMarker {
		return ""
	}
	return path
}

// IsAutomaticChoice reports whether a stored choice should use normal lookup
// (unset or empty). "do nothing" leaves the choice untouched, so it never
// records a sentinel.
func IsAutomaticChoice(choice string) bool {
	return choice == ""
}

// Resolve returns the absolute path of the tool binary: the recorded path when
// set and executable, otherwise the current PATH lookup, otherwise an error.
func Resolve(dataDir, name string) (string, error) {
	if recorded := RecordedPaths(dataDir)[name]; recorded != "" {
		if info, err := os.Stat(recorded); err == nil && info.Mode()&0o111 != 0 {
			return recorded, nil
		}
	}
	if found, err := exec.LookPath(name); err == nil {
		return found, nil
	}
	return "", fmt.Errorf("dependency %s not found; run `hlg-agent deps install %s`", name, name)
}

// RecordedPaths maps each managed tool name to the absolute path that should be
// written into the runtime config. Agent-managed binaries are recorded as their
// <data-dir>/deps path; apt tools as their PATH location.
func RecordedPaths(dataDir string) map[string]string {
	paths := map[string]string{}
	for _, tool := range All() {
		if ok, where := Check(dataDir, tool); ok {
			paths[tool.Name] = where
		}
	}
	return paths
}

// AppendPath exposes agent-managed binaries after system binaries in PATH.
func AppendPath(dataDir string) error {
	dir := DepsDir(dataDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := os.Getenv("PATH")
	if path == "" {
		return os.Setenv("PATH", dir)
	}
	for _, entry := range filepath.SplitList(path) {
		if entry == dir {
			return nil
		}
	}
	return os.Setenv("PATH", path+string(os.PathListSeparator)+dir)
}

// ManifestFile records the sha512 of every agent-managed (downloaded) binary so
// an upgrade can detect tampering/corruption and skip a redundant re-download.
const ManifestFile = "deps-manifest.json"

// Manifest is the on-disk record of managed binary hashes.
type Manifest struct {
	Binaries map[string]ManifestEntry `json:"binaries"`
}

type ManifestEntry struct {
	Path   string `json:"path"`
	SHA512 string `json:"sha512"`
	Origin string `json:"origin,omitempty"`
}

func manifestPath(dataDir string) string { return filepath.Join(DepsDir(dataDir), ManifestFile) }

func readManifest(dataDir string) Manifest {
	var m Manifest
	body, err := os.ReadFile(manifestPath(dataDir))
	if err != nil {
		return Manifest{Binaries: map[string]ManifestEntry{}}
	}
	if err := json.Unmarshal(body, &m); err != nil || m.Binaries == nil {
		return Manifest{Binaries: map[string]ManifestEntry{}}
	}
	return m
}

func writeManifest(dataDir string, m Manifest) error {
	if m.Binaries == nil {
		m.Binaries = map[string]ManifestEntry{}
	}
	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(manifestPath(dataDir), append(body, '\n'), 0o644)
}

func recordManifestEntry(dataDir, name, path, origin string) error {
	sha, err := fileSHA512(path)
	if err != nil {
		return err
	}
	m := readManifest(dataDir)
	m.Binaries[name] = ManifestEntry{Path: path, SHA512: sha, Origin: origin}
	return writeManifest(dataDir, m)
}

func fileSHA512(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha512.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// installBinary downloads a standalone binary and records its local hash.
func installBinary(ctx context.Context, controller string, dataDir string, tool Tool, force bool, logf func(string, ...any)) error {
	if !tool.Upstream && tool.Dist == "" {
		return fmt.Errorf("%s has no standalone binary", tool.Name)
	}
	path := BinaryPath(dataDir, tool.Name)
	if !tool.Upstream && !force {
		if info, err := os.Stat(path); err == nil && info.Mode()&0o111 != 0 {
			if entry, ok := readManifest(dataDir).Binaries[tool.Name]; ok && entry.SHA512 != "" {
				if actual, err := fileSHA512(path); err == nil && actual == entry.SHA512 {
					logf("deps: %s already installed (sha512 ok)", tool.Name)
					return nil
				}
				logf("deps: %s hash mismatch; reinstalling", tool.Name)
			} else {
				logf("deps: %s already installed", tool.Name)
				return nil
			}
		}
	}
	arch, err := runtimeArch()
	if err != nil {
		return err
	}
	fileName := tool.Dist
	if tool.Upstream {
		fileName = tool.UpstreamFile
	}
	fileName = strings.ReplaceAll(fileName, "{arch}", arch)
	if fileName == "" {
		return fmt.Errorf("%s has no build for %s", tool.Name, arch)
	}
	url, expected := "", ""
	if tool.Upstream {
		asset, err := fetchUpstreamAsset(ctx, controller, tool.Name, arch, fileName)
		if err != nil {
			return err
		}
		url, expected = asset.URL, asset.SHA256
	} else {
		if controller == "" {
			return fmt.Errorf("controller required for fallback download")
		}
		url = strings.TrimRight(controller, "/") + "/deps/" + fileName
		expected, err = fetchExpectedSHA256(ctx, controller, fileName)
		if err != nil {
			return err
		}
	}
	if !force {
		if info, err := os.Stat(path); err == nil && info.Mode()&0o111 != 0 {
			if tool.Upstream {
				if actual, hashErr := fileSHA256(path); hashErr == nil && actual == expected {
					if entry, ok := readManifest(dataDir).Binaries[tool.Name]; ok && entry.Origin == url {
						logf("deps: %s already installed (controller-published sha256 matches)", tool.Name)
						return nil
					}
				}
				logf("deps: %s differs from controller-published release; reinstalling", tool.Name)
			}
		}
	}
	if err := os.MkdirAll(DepsDir(dataDir), 0o755); err != nil {
		return err
	}
	logf("deps: downloading %s from %s", tool.Name, url)
	tmp := path + ".tmp"
	defer os.Remove(tmp)
	if err := downloadFile(ctx, url, tmp); err != nil {
		return err
	}
	actual, err := fileSHA256(tmp)
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("%s: SHA-256 mismatch (want %s, got %s)", tool.Name, expected, actual)
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if len(tool.Caps) > 0 {
		if err := applyCaps(tool.Caps, path); err != nil {
			logf("deps: warning: setcap %s: %v", path, err)
		}
	}
	if err := recordManifestEntry(dataDir, tool.Name, path, url); err != nil {
		logf("deps: warning: could not record hash for %s: %v", tool.Name, err)
	}
	logf("deps: installed %s at %s", tool.Name, path)
	return nil
}

type upstreamAsset struct {
	Version string `json:"version"`
	Name    string `json:"name"`
	Tool    string `json:"tool"`
	Arch    string `json:"arch"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	URL     string `json:"url"`
}

func fetchUpstreamAsset(ctx context.Context, controller, toolName, arch, fileName string) (upstreamAsset, error) {
	if controller == "" {
		return upstreamAsset{}, fmt.Errorf("controller required for upstream release digest")
	}
	resp, err := getWithContext(ctx, strings.TrimRight(controller, "/")+"/deps/manifest.json")
	if err != nil {
		return upstreamAsset{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return upstreamAsset{}, fmt.Errorf("deps manifest: %s", resp.Status)
	}
	var manifest struct {
		Upstream []upstreamAsset `json:"upstream"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&manifest); err != nil {
		return upstreamAsset{}, err
	}
	for _, asset := range manifest.Upstream {
		if asset.Tool != toolName || asset.Arch != arch || asset.Name != fileName {
			continue
		}
		if !validUpstreamVersion(asset.Version) || asset.Size <= 0 || len(asset.SHA256) != 64 {
			return upstreamAsset{}, fmt.Errorf("deps manifest has invalid upstream metadata for %s", fileName)
		}
		if _, err := hex.DecodeString(asset.SHA256); err != nil {
			return upstreamAsset{}, fmt.Errorf("deps manifest has invalid SHA-256 for %s", fileName)
		}
		parsed, err := url.Parse(asset.URL)
		if err != nil || parsed.Scheme != "https" || parsed.Host != "github.com" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "/nxtrace/NTrace-core/releases/download/"+asset.Version+"/"+fileName {
			return upstreamAsset{}, fmt.Errorf("deps manifest has invalid download URL for %s", fileName)
		}
		return asset, nil
	}
	return upstreamAsset{}, fmt.Errorf("deps manifest has no upstream SHA-256 for %s", fileName)
}

func validUpstreamVersion(version string) bool {
	if !strings.HasPrefix(version, "v") {
		return false
	}
	parts := strings.Split(version[1:], ".")
	if len(parts) < 2 || len(parts) > 4 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

func fetchExpectedSHA256(ctx context.Context, controller, fileName string) (string, error) {
	resp, err := getWithContext(ctx, strings.TrimRight(controller, "/")+"/deps/manifest.json")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("deps manifest: %s", resp.Status)
	}
	var manifest struct {
		Static []struct {
			Name   string `json:"name"`
			SHA256 string `json:"sha256"`
		} `json:"static"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&manifest); err != nil {
		return "", err
	}
	for _, entry := range manifest.Static {
		if entry.Name == fileName && len(entry.SHA256) == 64 {
			if _, err := hex.DecodeString(entry.SHA256); err == nil {
				return strings.ToLower(entry.SHA256), nil
			}
		}
	}
	return "", fmt.Errorf("deps manifest has no SHA-256 for %s", fileName)
}

// runtimeArch returns the Go arch name used in artifact file names.
func runtimeArch() (string, error) {
	switch runtime.GOARCH {
	case "amd64":
		return "amd64", nil
	case "arm64":
		return "arm64", nil
	default:
		return "", fmt.Errorf("unsupported architecture: %s", runtime.GOARCH)
	}
}

func getWithContext(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return (&http.Client{Timeout: 60 * time.Second}).Do(req)
}

// downloadFile GETs url and writes it to dest.
func downloadFile(ctx context.Context, url, dest string) error {
	resp, err := getWithContext(ctx, url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: %s", url, resp.Status)
	}
	file, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := io.Copy(file, resp.Body); err != nil {
		return err
	}
	return file.Close()
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// applyCaps sets file capabilities on each existing, symlink-resolved path. It
// is best-effort: missing setcap or a missing path is skipped, not fatal.
func applyCaps(caps []string, paths ...string) error {
	if len(caps) == 0 {
		return nil
	}
	if _, err := exec.LookPath("setcap"); err != nil {
		return nil
	}
	for _, path := range paths {
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			continue
		}
		if err := runCommand("setcap", strings.Join(caps, ",")+"+eip", resolved); err != nil {
			return err
		}
	}
	return nil
}

func runApt(args ...string) error {
	return runEnvCommand([]string{"DEBIAN_FRONTEND=noninteractive"}, "apt-get", args...)
}

func packageInstall(family, pkg string, force bool) error {
	switch family {
	case "apt":
		args := []string{"install", "-y"}
		if force {
			args = append(args, "--reinstall")
		}
		return runApt(append(args, pkg)...)
	case "dnf", "yum":
		verb := "install"
		if force {
			verb = "reinstall"
		}
		return runCommand(family, verb, "-y", pkg)
	case "apk":
		args := []string{"add", "--no-cache"}
		if force {
			args = append(args, "--force-reinstall")
		}
		return runCommand("apk", append(args, pkg)...)
	default:
		return fmt.Errorf("unsupported package manager %q", family)
	}
}

func packageUpgrade(family, pkg string) error {
	switch family {
	case "apt":
		return runApt("install", "--only-upgrade", "-y", pkg)
	case "dnf":
		return runCommand("dnf", "upgrade", "-y", pkg)
	case "yum":
		return runCommand("yum", "update", "-y", pkg)
	case "apk":
		return runCommand("apk", "upgrade", pkg)
	default:
		return fmt.Errorf("unsupported package manager %q", family)
	}
}

// packageUpdateAvailable is intentionally not implemented for the system package
// manager: only the agent-managed downloads (iperf3 via Dist, nexttrace via
// upstream) are checked for updates. Package tools are upgraded directly.
// (Removed the apt/apk probing: the controller binary is the one whose version
// we control and can compare.)

func runEnvCommand(env []string, name string, args ...string) error {
	if _, err := exec.LookPath(name); err != nil {
		return fmt.Errorf("%s is not available", name)
	}
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), env...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func runCommand(name string, args ...string) error {
	output, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}
