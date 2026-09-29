package deps

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckBinary(t *testing.T) {
	dir := t.TempDir()
	tool := Tool{Name: "hlg-definitely-not-a-real-tool", Kind: KindBinary}
	if ok, _ := Check(dir, tool); ok {
		t.Fatal("Check reported an uninstalled tool as present")
	}
	path := BinaryPath(dir, tool.Name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	ok, detail := Check(dir, tool)
	if !ok || detail != path {
		t.Fatalf("Check = %v, %q; want true, %q", ok, detail, path)
	}
	// A non-executable file is reported as broken, not installed.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if ok, _ := Check(dir, tool); ok {
		t.Fatal("Check accepted a non-executable file")
	}
}

func TestCheckManagedSHA512(t *testing.T) {
	dataDir := t.TempDir()
	if _, _, managed, err := CheckManagedSHA512(dataDir, "nexttrace"); err != nil || managed {
		t.Fatalf("unmanaged binary check = managed %v, err %v", managed, err)
	}
	path := BinaryPath(dataDir, "nexttrace")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("managed-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := recordManifestEntry(dataDir, "nexttrace", path, "test"); err != nil {
		t.Fatal(err)
	}
	expected, actual, managed, err := CheckManagedSHA512(dataDir, "nexttrace")
	if err != nil || !managed || expected == "" || expected != actual {
		t.Fatalf("managed binary check = expected %q actual %q managed %v err %v", expected, actual, managed, err)
	}
	if err := os.WriteFile(path, []byte("modified"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, actual, managed, err = CheckManagedSHA512(dataDir, "nexttrace")
	if err != nil || !managed || actual == expected {
		t.Fatalf("tampered binary check = expected %q actual %q managed %v err %v", expected, actual, managed, err)
	}
}

func TestEffectiveRespectsRecordedChoice(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(DepsDir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	// A downloaded copy under data/deps.
	dataPath := BinaryPath(dir, "nexttrace")
	if err := os.WriteFile(dataPath, []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Explicit download path wins over anything on PATH.
	ok, where := Effective(map[string]string{"nexttrace": dataPath}, dir, "nexttrace")
	if !ok || where != dataPath {
		t.Fatalf("recorded download path not honored: %v %q", ok, where)
	}

	// builtin -> the built-in probe.
	if ok, where := Effective(map[string]string{"mtr": BuiltinMarker}, dir, "mtr"); !ok || where != BuiltinMarker {
		t.Fatalf("builtin not honored: %v %q", ok, where)
	}

	// Unset / empty -> automatic lookup.
	if !IsAutomaticChoice("") {
		t.Fatal("empty choice must be automatic")
	}
	t.Setenv("PATH", t.TempDir())
	if ok, where := Effective(map[string]string{"mtr": ""}, dir, "mtr"); !ok || where != BuiltinMarker {
		t.Fatalf("empty choice should use automatic built-in fallback, got %v %q", ok, where)
	}
}

func TestEffectiveAutoFallsBackToDataDirCopy(t *testing.T) {
	dir := t.TempDir()
	// No recorded entry: automatic resolution. A data-dir copy is used when no
	// system binary exists.
	if err := os.MkdirAll(DepsDir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(BinaryPath(dir, "nexttrace"), []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if ok, where := Effective(map[string]string{}, dir, "nexttrace"); !ok || where != BinaryPath(dir, "nexttrace") {
		t.Fatalf("auto should fall back to the data-dir copy: %v %q", ok, where)
	}
}

func TestControllerFallbackHash(t *testing.T) {
	const file = "hlg-iperf3-linux-amd64"
	bytes := []byte("binary")
	digest := sha256.Sum256(bytes)
	expected := hex.EncodeToString(digest[:])
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/deps/manifest.json":
			_, _ = w.Write([]byte(`{"static":[{"name":"` + file + `","sha256":"` + expected + `"}]}`))
		case "/deps/" + file:
			_, _ = w.Write(bytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	actual, err := fetchExpectedSHA256(context.Background(), server.URL, file)
	if err != nil || actual != expected {
		t.Fatalf("manifest hash = %q, %v", actual, err)
	}
	path := filepath.Join(t.TempDir(), file)
	if err := downloadFile(context.Background(), server.URL+"/deps/"+file, path); err != nil {
		t.Fatal(err)
	}
	actual, err = fileSHA256(path)
	if err != nil || actual != expected {
		t.Fatalf("download hash = %q, %v", actual, err)
	}
}

func TestInstallDownloadedVerifiesControllerHash(t *testing.T) {
	arch, err := runtimeArch()
	if err != nil {
		t.Skip(err)
	}
	name := "hlg-iperf3-linux-" + arch
	digest := sha256.Sum256([]byte("expected binary"))
	serveWrong := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/deps/manifest.json" {
			_, _ = w.Write([]byte(`{"static":[{"name":"` + name + `","sha256":"` + hex.EncodeToString(digest[:]) + `"}]}`))
			return
		}
		if serveWrong {
			_, _ = w.Write([]byte("wrong binary"))
		} else {
			_, _ = w.Write([]byte("expected binary"))
		}
	}))
	defer server.Close()
	dir := t.TempDir()
	_, err = InstallDownloaded(context.Background(), server.URL, dir, registry["iperf3"], false, func(string, ...any) {})
	if err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("expected checksum rejection, got %v", err)
	}
	if _, statErr := os.Stat(BinaryPath(dir, "iperf3")); !os.IsNotExist(statErr) {
		t.Fatalf("unverified binary was installed: %v", statErr)
	}
	serveWrong = false
	path, err := InstallDownloaded(context.Background(), server.URL, dir, registry["iperf3"], false, func(string, ...any) {})
	if err != nil || path != BinaryPath(dir, "iperf3") {
		t.Fatalf("verified install: path=%q err=%v", path, err)
	}
	if readManifest(dir).Binaries["iperf3"].SHA512 == "" {
		t.Fatal("installed binary has no local integrity record")
	}
}

func TestUpgradeManagedKeepsSystemIperf3Untouched(t *testing.T) {
	arch, err := runtimeArch()
	if err != nil {
		t.Skip(err)
	}
	const newBinary = "new managed iperf3"
	name := "hlg-iperf3-linux-" + arch
	digest := sha256.Sum256([]byte(newBinary))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/deps/manifest.json":
			_, _ = w.Write([]byte(`{"static":[{"name":"` + name + `","sha256":"` + hex.EncodeToString(digest[:]) + `"}]}`))
		case "/deps/" + name:
			_, _ = w.Write([]byte(newBinary))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	systemDir := t.TempDir()
	systemPath := filepath.Join(systemDir, "iperf3")
	if err := os.WriteFile(systemPath, []byte("system iperf3"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", systemDir)
	dataDir := t.TempDir()
	managedPath := BinaryPath(dataDir, "iperf3")
	if err := os.MkdirAll(filepath.Dir(managedPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managedPath, []byte("old managed iperf3"), 0o755); err != nil {
		t.Fatal(err)
	}
	updated, err := UpgradeManaged(context.Background(), server.URL, dataDir, registry["iperf3"], func(string, ...any) {})
	if err != nil || !updated {
		t.Fatalf("managed upgrade: updated=%v err=%v", updated, err)
	}
	if got, err := os.ReadFile(managedPath); err != nil || string(got) != newBinary {
		t.Fatalf("managed binary = %q, %v", got, err)
	}
	if got, err := os.ReadFile(systemPath); err != nil || string(got) != "system iperf3" {
		t.Fatalf("system binary changed: %q, %v", got, err)
	}
	updated, err = UpgradeManaged(context.Background(), server.URL, dataDir, registry["iperf3"], func(string, ...any) {})
	if err != nil || updated {
		t.Fatalf("matching managed binary should be current: updated=%v err=%v", updated, err)
	}
}

func TestControllerPublishedNexttraceDigestSkipsMatchingDownload(t *testing.T) {
	arch, err := runtimeArch()
	if err != nil {
		t.Skip(err)
	}
	contents := []byte("controller-published nexttrace")
	digest := sha256.Sum256(contents)
	fileName := "nexttrace_linux_" + arch
	origin := "https://github.com/nxtrace/NTrace-core/releases/download/v1.7.3/" + fileName
	manifest := fmt.Sprintf(`{"upstream":[{"tool":"nexttrace","arch":%q,"version":"v1.7.3","name":%q,"sha256":%q,"size":%d,"url":%q}]}`,
		arch, fileName, hex.EncodeToString(digest[:]), len(contents), origin)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/deps/manifest.json" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(manifest))
	}))
	defer server.Close()
	dataDir := t.TempDir()
	path := BinaryPath(dataDir, "nexttrace")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, contents, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := recordManifestEntry(dataDir, "nexttrace", path, origin); err != nil {
		t.Fatal(err)
	}
	if needed, _ := updateAvailable(context.Background(), server.URL, dataDir, registry["nexttrace"]); needed {
		t.Fatal("matching controller-published NextTrace release requested another download")
	}
	if err := os.WriteFile(path, []byte("changed nexttrace"), 0o755); err != nil {
		t.Fatal(err)
	}
	if needed, _ := updateAvailable(context.Background(), server.URL, dataDir, registry["nexttrace"]); !needed {
		t.Fatal("modified nexttrace was treated as current")
	}
}

func TestPackagesCoverAllManagers(t *testing.T) {
	families := []string{"apt", "dnf", "yum", "apk"}
	for _, tool := range All() {
		if tool.Kind != KindPackage {
			continue
		}
		for _, family := range families {
			if tool.Packages[family] == "" {
				t.Errorf("%s has no %s package", tool.Name, family)
			}
		}
	}
}

func TestManifestRoundTripAndIntegrity(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(DepsDir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	path := BinaryPath(dir, "nexttrace")
	if err := os.WriteFile(path, []byte("payload"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := recordManifestEntry(dir, "nexttrace", path, "https://example/bin"); err != nil {
		t.Fatal(err)
	}
	entry, ok := readManifest(dir).Binaries["nexttrace"]
	if !ok || entry.SHA512 == "" || entry.Path != path {
		t.Fatalf("manifest entry = %+v ok=%v", entry, ok)
	}
	// The recorded hash matches the file now.
	actual, err := fileSHA512(path)
	if err != nil {
		t.Fatal(err)
	}
	if actual != entry.SHA512 {
		t.Fatalf("hash mismatch: %s != %s", actual, entry.SHA512)
	}
	// Tampering changes the hash, so an upgrade would reinstall.
	if err := os.WriteFile(path, []byte("tampered"), 0o755); err != nil {
		t.Fatal(err)
	}
	tampered, _ := fileSHA512(path)
	if tampered == entry.SHA512 {
		t.Fatal("tampered file still matches the recorded hash")
	}
}
