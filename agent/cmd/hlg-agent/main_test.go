package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hlg/internal/certstore"
	"hlg/internal/config"
	"hlg/internal/deps"
	"hlg/internal/enroll"
)

func TestDepsNothingPreservesCurrentSource(t *testing.T) {
	oldTools, oldChanged := chosenTools, depsConfigChanged
	defer func() {
		chosenTools, depsConfigChanged = oldTools, oldChanged
	}()

	tool, err := deps.Lookup("mtr")
	if err != nil {
		t.Fatal(err)
	}
	chosenTools = map[string]string{"mtr": deps.BuiltinMarker}
	depsConfigChanged = false
	logf := func(string, ...any) {}

	if err := applyDepsSource(context.Background(), "", t.TempDir(), tool, "nothing", "", logf); err != nil {
		t.Fatal(err)
	}
	if got := chosenTools["mtr"]; got != deps.BuiltinMarker {
		t.Fatalf("deps config nothing changed source to %q", got)
	}
	if depsConfigChanged {
		t.Fatal("deps config nothing marked sources changed")
	}

	applyDepsChoice(context.Background(), "", t.TempDir(), tool, "nothing")
	if got := chosenTools["mtr"]; got != deps.BuiltinMarker {
		t.Fatalf("initial dependency nothing changed source to %q", got)
	}
}

func TestSelectCommandDefaultsToHelp(t *testing.T) {
	command, args := selectCommand(nil)
	if command != "help" || len(args) != 0 {
		t.Fatalf("selectCommand(nil) = %q, %v", command, args)
	}
	command, args = selectCommand([]string{"run", "-i", "-k", "lginit_key"})
	if command != "run" || len(args) != 3 || args[0] != "-i" {
		t.Fatalf("selectCommand(run...) = %q, %v", command, args)
	}
}

func TestBindWithPortKeepsAddressAndValidatesPort(t *testing.T) {
	for _, test := range []struct {
		name, bind, port, want string
	}{
		{name: "all interfaces", bind: ":443", port: "9443", want: ":9443"},
		{name: "IPv6 host", bind: "[::1]:443", port: "8443", want: "[::1]:8443"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := bindWithPort(test.bind, test.port)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("bindWithPort(%q, %q) = %q, want %q", test.bind, test.port, got, test.want)
			}
		})
	}
	for _, port := range []string{"0", "65536", "abc", ""} {
		if _, err := bindWithPort(":443", port); err == nil {
			t.Errorf("bindWithPort(\":443\", %q) accepted an invalid port", port)
		}
	}
}

func TestRunInitCredentialsRequireExplicitInitFlag(t *testing.T) {
	const key = "lginit_abcdefghijklmnopqrst"
	controller, resolved, err := resolveRunInitInputs(false, "", "", "invalid-key")
	if err != nil || controller != "" || resolved != "" {
		t.Fatalf("run without -i consumed key: controller=%q key=%q err=%v", controller, resolved, err)
	}
	controller, resolved, err = resolveRunInitInputs(true, "https://lg.example", "", key)
	if err != nil || controller != "https://lg.example" || resolved != key {
		t.Fatalf("run -i did not resolve credentials: controller=%q key=%q err=%v", controller, resolved, err)
	}
}

func TestRunInitCanReadControllerFromConfigPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(path, []byte(`{"controller":"https://lg.example"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := controllerFromConfigFile(path); got != "https://lg.example" {
		t.Fatalf("controllerFromConfigFile() = %q", got)
	}
}

func TestRunInitBootstrapsIntoMountedConfigAndReusesStoredIdentity(t *testing.T) {
	dataDir := t.TempDir()
	configPath := filepath.Join(dataDir, "agent.json")
	if err := os.WriteFile(configPath, []byte(`{"log_level":"debug","init_token":"stale"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{DataDir: dataDir, Bind: ":8443", InitString: "lg.example/lginit_abcdefghijklmnopqrst"}
	fresh, err := prepareRunBootstrap(&cfg, true, config.Config{})
	if err != nil || !fresh || cfg.Controller != "https://lg.example" || cfg.InitToken != "lginit_abcdefghijklmnopqrst" {
		t.Fatalf("fresh run -i: fresh=%v controller=%q key=%q err=%v", fresh, cfg.Controller, cfg.InitToken, err)
	}
	cfg.NodeID = "node-1"
	if err := persistRunBootstrapConfig(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	record := readRawConfig(configPath)
	if record["controller"] != cfg.Controller || record["node_id"] != cfg.NodeID || record["data_dir"] != dataDir || record["bind"] != cfg.Bind || record["log_level"] != "debug" {
		t.Fatalf("unexpected persisted config: %v", record)
	}
	if _, ok := record["init_token"]; ok {
		t.Fatal("one-time key persisted in agent.json")
	}
	if err := os.WriteFile(filepath.Join(dataDir, "node-token"), []byte("stored-node-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(config.LoadOptions{File: configPath})
	if err != nil {
		t.Fatal(err)
	}
	loaded.InitString = "invalid key left in container environment"
	fresh, err = prepareRunBootstrap(&loaded, true, config.Config{})
	if err != nil || fresh || loaded.InitToken != "" || loaded.InitString != "" || loaded.Controller != cfg.Controller {
		t.Fatalf("stored run -i: fresh=%v controller=%q key=%q init_string=%q err=%v", fresh, loaded.Controller, loaded.InitToken, loaded.InitString, err)
	}
}

func TestRunWithoutInitIgnoresCommandAndEnvironmentKeys(t *testing.T) {
	cfg := config.Config{DataDir: t.TempDir(), InitToken: "lginit_abcdefghijklmnopqrst", InitString: "lg.example/lginit_abcdefghijklmnopqrst"}
	fresh, err := prepareRunBootstrap(&cfg, false, config.Config{})
	if err != nil || fresh || cfg.InitToken != "" || cfg.InitString != "" || cfg.Controller != "" {
		t.Fatalf("plain run consumed init credentials: fresh=%v cfg=%+v err=%v", fresh, cfg, err)
	}
}

func TestUpgradeOnlySelectsEffectiveManagedDependencies(t *testing.T) {
	t.Setenv("PATH", "")
	dataDir := t.TempDir()
	managedPath := deps.BinaryPath(dataDir, "iperf3")
	if err := os.MkdirAll(filepath.Dir(managedPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managedPath, []byte("managed"), 0o755); err != nil {
		t.Fatal(err)
	}
	customPath := filepath.Join(t.TempDir(), "iperf3")
	if err := os.WriteFile(customPath, []byte("custom"), 0o755); err != nil {
		t.Fatal(err)
	}
	iperfTool, _ := deps.Lookup("iperf3")
	mtrTool, _ := deps.Lookup("mtr")
	if !usesManagedDependency(map[string]string{"iperf3": managedPath}, dataDir, iperfTool) {
		t.Fatal("explicit managed iperf3 was skipped")
	}
	if !usesManagedDependency(nil, dataDir, iperfTool) {
		t.Fatal("automatic managed fallback was skipped")
	}
	if usesManagedDependency(map[string]string{"iperf3": customPath}, dataDir, iperfTool) {
		t.Fatal("custom iperf3 was selected for managed upgrade")
	}
	if usesManagedDependency(map[string]string{"mtr": deps.BuiltinMarker}, dataDir, mtrTool) {
		t.Fatal("built-in mtr was selected for package upgrade")
	}
}

func TestDoctorChecksOnlyTheEffectiveDependency(t *testing.T) {
	dataDir := t.TempDir()
	managedPath := deps.BinaryPath(dataDir, "iperf3")
	if err := os.MkdirAll(filepath.Dir(managedPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managedPath, []byte("stale managed copy"), 0o755); err != nil {
		t.Fatal(err)
	}
	manifest, err := json.Marshal(deps.Manifest{Binaries: map[string]deps.ManifestEntry{
		"iperf3": {Path: managedPath, SHA512: strings.Repeat("0", 128)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deps.DepsDir(dataDir), deps.ManifestFile), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	systemPath := filepath.Join(t.TempDir(), "iperf3")
	if err := os.WriteFile(systemPath, []byte("selected system copy"), 0o755); err != nil {
		t.Fatal(err)
	}
	tool, err := deps.Lookup("iperf3")
	if err != nil {
		t.Fatal(err)
	}
	if problems := checkDoctorDependency(tool, systemPath, dataDir, ""); len(problems) != 0 {
		t.Fatalf("system source reported stale managed copy: %v", problems)
	}
	mtrTool, err := deps.Lookup("mtr")
	if err != nil {
		t.Fatal(err)
	}
	if problems := checkDoctorDependency(mtrTool, deps.BuiltinMarker, dataDir, ""); len(problems) != 0 {
		t.Fatalf("built-in source reported stale managed copy: %v", problems)
	}
	if problems := checkDoctorDependency(tool, managedPath, dataDir, ""); len(problems) != 1 || !strings.Contains(problems[0], "sha512 mismatch") {
		t.Fatalf("selected managed copy did not report its mismatch: %v", problems)
	}
}

func TestMissingToolAutomaticSourcePreference(t *testing.T) {
	if got := missingToolDefault(deps.Tool{Name: "mtr"}, true); got != "builtin" {
		t.Fatalf("builtin probe default = %q, want builtin", got)
	}
	if got := missingToolDefault(deps.Tool{Name: "nexttrace"}, true); got != "download" {
		t.Fatalf("standalone default = %q, want download", got)
	}
	if got := missingToolDefault(deps.Tool{Name: "hlg-no-such-tool"}, false); got != "nothing" {
		t.Fatalf("unsupported tool default = %q, want nothing", got)
	}
}

func TestRunInitReusesManagedDependencyFromDataDir(t *testing.T) {
	previousTools, previousConfigPath := chosenTools, depsConfigPath
	t.Cleanup(func() {
		chosenTools = previousTools
		depsConfigPath = previousConfigPath
	})

	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"iperf3", "mtr", "ping", "traceroute"} {
		path := filepath.Join(binDir, name)
		if err := os.WriteFile(path, []byte("tool"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", binDir)

	dataDir := filepath.Join(root, "data")
	managedPath := deps.BinaryPath(dataDir, "nexttrace")
	if err := os.MkdirAll(filepath.Dir(managedPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managedPath, []byte("managed tool"), 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "agent.json")
	if err := os.WriteFile(configPath, []byte(`{"tools":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Controller: "https://lg.example", DataDir: dataDir, Tools: map[string]string{}}
	ensureRunDependencies(context.Background(), &cfg, configPath)

	if cfg.Tools["nexttrace"] != managedPath {
		t.Fatalf("run -i selected nexttrace path %q, want existing managed path %q", cfg.Tools["nexttrace"], managedPath)
	}
	if got := readRawConfig(configPath)["tools"].(map[string]any)["nexttrace"]; got != managedPath {
		t.Fatalf("run -i did not persist the managed nexttrace path: %v", got)
	}
}

func stubInstallPortProbe(t *testing.T) {
	t.Helper()
	previous := portInUse
	portInUse = func(string) (bool, string) { return false, "" }
	t.Cleanup(func() { portInUse = previous })
}

func TestStoreBootstrapStateReturnsPersistenceErrors(t *testing.T) {
	dataFile := t.TempDir() + "/not-a-directory"
	if err := os.WriteFile(dataFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := enroll.NewClient(config.Config{DataDir: dataFile})

	err := storeBootstrapState(client, enroll.BootstrapResponse{
		NodeToken: "node-token",
		Config:    config.SignedBundle{NodeID: "testnode01"},
	})
	if err == nil {
		t.Fatal("expected persistence error")
	}
}

func TestNormalizeServiceMode(t *testing.T) {
	t.Setenv("PATH", os.Getenv("PATH"))

	mode, err := normalizeServiceMode("systemd", false)
	if err != nil || mode != "systemd" {
		t.Fatalf("normalize explicit systemd = %q, %v", mode, err)
	}

	mode, err = normalizeServiceMode("none", false)
	if err != nil || mode != "none" {
		t.Fatalf("normalize explicit none = %q, %v", mode, err)
	}

	mode, err = normalizeServiceMode("auto", true)
	if err != nil || mode != "all" {
		t.Fatalf("normalize auto uninstall = %q, %v", mode, err)
	}
}

func TestDiscoverBootstrapInputReadsCandidate(t *testing.T) {
	dir := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "bootstrap-input.json")
	if err := os.WriteFile(path, []byte(`{"controller":"https://lg.example","init_token":"lginit_test","node_id":"sg-1"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, discovered, err := discoverBootstrapInput()
	if err != nil {
		t.Fatal(err)
	}
	if discovered != path {
		t.Fatalf("discovered path = %q", discovered)
	}
	if cfg.Controller != "https://lg.example" || cfg.InitToken != "lginit_test" || cfg.NodeID != "sg-1" {
		t.Fatalf("bootstrap cfg = %#v", cfg)
	}
}

func TestSyncIntervalTracksCertificateState(t *testing.T) {
	dir := t.TempDir()
	store := certstore.New(dir)
	cfg := config.Defaults()

	// No managed certificate -> fast retry cadence.
	if got := syncInterval(cfg, store); got != 5*time.Minute {
		t.Fatalf("no-cert interval = %v, want 5m", got)
	}

	// Managed certificate present -> healthy cadence from config.
	if _, _, err := store.EnsureSelfSigned("edge01.example.net"); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteSource(certstore.CertSourceManaged); err != nil {
		t.Fatal(err)
	}
	cfg.SyncIntervalHealthySeconds = 3600
	if got := syncInterval(cfg, store); got != time.Hour {
		t.Fatalf("managed interval = %v, want 1h", got)
	}

	// Zero limit falls back to 45 minutes.
	cfg.SyncIntervalHealthySeconds = 0
	if got := syncInterval(cfg, store); got != 45*time.Minute {
		t.Fatalf("fallback interval = %v, want 45m", got)
	}
}

func TestDynamicCertificateCachesUntilMtimeChanges(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	writeKeyPair := func(domain string) {
		t.Helper()
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			t.Fatal(err)
		}
		template := x509.Certificate{
			SerialNumber:          serial,
			Subject:               pkix.Name{CommonName: domain},
			DNSNames:              []string{domain},
			NotBefore:             time.Now().Add(-time.Minute),
			NotAfter:              time.Now().Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	writeKeyPair("first.example.net")
	getCertificate := dynamicCertificate(certPath, keyPath)
	first, err := getCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, leafErr := x509.ParseCertificate(first.Certificate[0])
	if leafErr != nil {
		t.Fatal(leafErr)
	}
	if leaf.Subject.CommonName != "first.example.net" {
		t.Fatalf("leaf CN = %q", leaf.Subject.CommonName)
	}

	// Same mtime: must serve the cached certificate, not re-read the files.
	same, err := getCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if same != first {
		t.Fatal("expected cached *tls.Certificate instance for unchanged files")
	}

	// A key-only rotation must trigger a reload even when the cert timestamp
	// has not changed (the certificate contents still need to match the key).
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	keyMod := keyInfo.ModTime().Add(5 * time.Second)
	if err := os.Chtimes(keyPath, keyMod, keyMod); err != nil {
		t.Fatal(err)
	}
	keyReload, err := getCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if keyReload == first {
		t.Fatal("expected reload after key-only mtime change")
	}

	// Rewrite with a bumped mtime: must reload.
	writeKeyPair("second.example.net")
	if err := os.Chtimes(certPath, time.Now().Add(10*time.Second), time.Now().Add(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(keyPath, time.Now().Add(10*time.Second), time.Now().Add(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	second, err := getCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Fatal("expected reload after mtime change")
	}
	if len(second.Certificate) == 0 {
		t.Fatal("reloaded certificate missing chain")
	}
	reloaded, err := x509.ParseCertificate(second.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Subject.CommonName != "second.example.net" {
		t.Fatalf("reloaded leaf CN = %q", reloaded.Subject.CommonName)
	}
}

func TestDynamicCertificateServesCachedPairOnTransientReadError(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	writeKeyPair := func(domain string) {
		t.Helper()
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			t.Fatal(err)
		}
		template := x509.Certificate{
			SerialNumber:          serial,
			Subject:               pkix.Name{CommonName: domain},
			DNSNames:              []string{domain},
			NotBefore:             time.Now().Add(-time.Minute),
			NotAfter:              time.Now().Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeKeyPair("cache.example.net")
	getCertificate := dynamicCertificate(certPath, keyPath)
	if _, err := getCertificate(nil); err != nil {
		t.Fatal(err)
	}

	// Transient failure: corrupt the key file AND bump the cert mtime so the
	// cache would try to reload; the previously cached pair must be served.
	if err := os.WriteFile(keyPath, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(certPath, time.Now().Add(time.Second), time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	cert, err := getCertificate(nil)
	if err != nil {
		t.Fatalf("cached cert not served after transient load error: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("cached certificate missing chain")
	}
	cachedLeaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if cachedLeaf.Subject.CommonName != "cache.example.net" {
		t.Fatalf("unexpected cached cert CN = %q", cachedLeaf.Subject.CommonName)
	}
}

func TestMaskSecretDoesNotLogSecretPrefix(t *testing.T) {
	secret := "lginit_some-very-sensitive-value"
	masked := maskSecret(secret)
	if strings.Contains(masked, secret[:8]) {
		t.Fatalf("masked fingerprint contains secret prefix: %q", masked)
	}
	if masked != maskSecret(secret) || masked == "" {
		t.Fatalf("unexpected secret fingerprint: %q", masked)
	}
}

func TestRunInstallWritesRuntimeAndBootstrapFiles(t *testing.T) {
	stubInstallDeps(t)
	stubInstallPortProbe(t)
	dir := t.TempDir()
	installDir := filepath.Join(dir, "opt", "looking-glass")
	dataDir := filepath.Join(installDir, "data")
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(installDir, "hlg-agent"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := runInstall("", installDir, dataDir, "none", "root", "hlg-agent", "hlg-agent", "https://lg.example", "lginit_test", "sg-1", ":9443", "https://lg.example", "debug", "/var/log/hlg-agent.log", false); err != nil {
		t.Fatal(err)
	}

	var runtimeCfg map[string]any
	runtimeBody, err := os.ReadFile(filepath.Join(installDir, "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(runtimeBody, &runtimeCfg); err != nil {
		t.Fatal(err)
	}
	if runtimeCfg["controller"] != "https://lg.example" || runtimeCfg["node_id"] != "sg-1" || runtimeCfg["data_dir"] != dataDir {
		t.Fatalf("runtime cfg = %#v", runtimeCfg)
	}
	if runtimeCfg["log_level"] != "debug" || runtimeCfg["log_file"] != "/var/log/hlg-agent.log" {
		t.Fatalf("log settings not persisted: %#v", runtimeCfg)
	}
	if runtimeCfg["bind"] != ":9443" {
		t.Fatalf("bind not persisted: %#v", runtimeCfg)
	}

	var bootstrapCfg map[string]any
	bootstrapBody, err := os.ReadFile(filepath.Join(installDir, "bootstrap-input.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(bootstrapBody, &bootstrapCfg); err != nil {
		t.Fatal(err)
	}
	if bootstrapCfg["init_token"] != "lginit_test" {
		t.Fatalf("bootstrap cfg = %#v", bootstrapCfg)
	}
	if bootstrapCfg["bind"] != ":9443" {
		t.Fatalf("bootstrap bind not persisted: %#v", bootstrapCfg)
	}
	// The install layout is recorded so maintenance commands (--update,
	// --self-check, --uninstall) act on the custom names, not flag defaults.
	if runtimeCfg["install_dir"] != installDir || runtimeCfg["binary_name"] != "hlg-agent" || runtimeCfg["service_name"] != "hlg-agent" || runtimeCfg["service_mode"] != "none" {
		t.Fatalf("install layout not recorded: %#v", runtimeCfg)
	}
}

func TestRunInstallRejectsMissingServiceUserBeforeWritingFiles(t *testing.T) {
	installDir := filepath.Join(t.TempDir(), "install")
	err := runInstall("", installDir, filepath.Join(installDir, "data"), "none", "hlg-service-user-does-not-exist", "hlg-agent", "hlg-agent", "https://lg.example", "lginit_test", "", ":9443", "", "", "", true)
	if err == nil || !strings.Contains(err.Error(), "service user") {
		t.Fatalf("runInstall missing service user error = %v", err)
	}
	if _, statErr := os.Stat(installDir); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("runInstall changed install dir before validating user: %v", statErr)
	}
}

func TestInstallDefaultsBindTo443(t *testing.T) {
	if got := config.Defaults().Bind; got != ":443" {
		t.Fatalf("default bind = %q, want :443", got)
	}
}

func TestResolveInstallIdentityUsesRecordedLayout(t *testing.T) {
	dir := t.TempDir()
	installDir := filepath.Join(dir, "srv", "lg")
	dataDir := filepath.Join(installDir, "state")
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A custom binary/service name, plus a non-default data dir.
	cfg := map[string]any{
		"controller":   "https://lg.example",
		"install_dir":  installDir,
		"data_dir":     dataDir,
		"binary_name":  "my-agent",
		"service_name": "my-agent-svc",
		"service_mode": "systemd",
	}
	body, _ := json.Marshal(cfg)
	configPath := filepath.Join(installDir, "agent.json")
	if err := os.WriteFile(configPath, body, 0o600); err != nil {
		t.Fatal(err)
	}

	// No flags passed: the recorded layout must win over the running binary and
	// the compiled defaults.
	identity, err := resolveInstallIdentity(map[string]bool{}, configPath, "", "", "auto", "hlg-agent", "hlg-agent")
	if err != nil {
		t.Fatal(err)
	}
	if identity.InstallDir != installDir || identity.BinaryName != "my-agent" || identity.ServiceName != "my-agent-svc" || identity.ServiceMode != "systemd" || identity.DataDir != dataDir {
		t.Fatalf("identity = %+v", identity)
	}
	if identity.ExplicitTarget {
		t.Fatalf("no layout flags were passed; ExplicitTarget must be false: %+v", identity)
	}

	// An explicit flag overrides the recorded value.
	identity, err = resolveInstallIdentity(map[string]bool{"service-name": true}, configPath, "", "", "auto", "hlg-agent", "override-svc")
	if err != nil {
		t.Fatal(err)
	}
	if identity.ServiceName != "override-svc" {
		t.Fatalf("explicit flag should win: %+v", identity)
	}
	// ...but the rest still comes from the install record.
	if identity.BinaryName != "my-agent" || identity.InstallDir != installDir {
		t.Fatalf("recorded layout lost: %+v", identity)
	}
}

// stubExecutable points executablePath at a fake installed binary for the test
// duration and stubs the service unit directories.
func stubExecutable(t *testing.T, exe string) {
	t.Helper()
	origExe := executablePath
	origSystemd := systemdUnitDir
	origInit := openrcInitDir
	executablePath = func() string { return exe }
	systemdUnitDir = filepath.Join(t.TempDir(), "systemd")
	openrcInitDir = filepath.Join(t.TempDir(), "init.d")
	if err := os.MkdirAll(systemdUnitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(openrcInitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		executablePath = origExe
		systemdUnitDir = origSystemd
		openrcInitDir = origInit
	})
}

// stubInstallDeps makes installDepsInteractive a no-op so --install tests never
// touch the package manager.
func stubInstallDeps(t *testing.T) {
	t.Helper()
	orig := installDepsInteractive
	installDepsInteractive = func(context.Context, string, string, bool) error { return nil }
	t.Cleanup(func() { installDepsInteractive = orig })
}

// TestResolveInstallIdentityDerivesFromExecutable covers the core fix: an agent
// running from its install location (custom dir, custom binary name, no flags)
// must resolve its own layout instead of the compiled-in hlg-agent defaults.
func TestResolveInstallIdentityDerivesFromExecutable(t *testing.T) {
	installDir := filepath.Join(t.TempDir(), "srv", "lg")
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(installDir, "my-agent")
	// agent.json sits next to the binary, without any recorded layout (the
	// legacy shape) — the binary itself is the source of truth.
	if err := os.WriteFile(filepath.Join(installDir, "agent.json"), []byte(`{"controller":"https://lg.example"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	stubExecutable(t, exe)

	identity, err := resolveInstallIdentity(map[string]bool{}, "", "", "", "auto", "hlg-agent", "hlg-agent")
	if err != nil {
		t.Fatal(err)
	}
	if identity.InstallDir != installDir {
		t.Fatalf("install dir = %q, want %q", identity.InstallDir, installDir)
	}
	if identity.BinaryName != "my-agent" {
		t.Fatalf("binary name = %q, want my-agent", identity.BinaryName)
	}
	// No unit launches this binary and no service name is recorded: fall back to
	// the binary name rather than the compiled-in default.
	if identity.ServiceName != "my-agent" {
		t.Fatalf("service name = %q, want my-agent", identity.ServiceName)
	}
	if identity.DataDir != filepath.Join(installDir, "data") {
		t.Fatalf("data dir = %q", identity.DataDir)
	}
	if identity.ConfigFile != filepath.Join(installDir, "agent.json") {
		t.Fatalf("config file = %q", identity.ConfigFile)
	}
}

// The service name must be recovered from the unit that launches the binary, so
// --update restarts the service the node actually runs even when agent.json
// predates the recorded layout and the service name differs from the binary.
func TestResolveInstallIdentityDiscoversServiceNameFromUnit(t *testing.T) {
	installDir := filepath.Join(t.TempDir(), "srv", "lg")
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(installDir, "my-agent")
	if err := os.WriteFile(filepath.Join(installDir, "agent.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	stubExecutable(t, exe)

	unit := fmt.Sprintf("[Service]\nExecStart=%s --config %s\n", exe, filepath.Join(installDir, "agent.json"))
	if err := os.WriteFile(filepath.Join(systemdUnitDir, "custom-lg.service"), []byte(unit), 0o644); err != nil {
		t.Fatal(err)
	}

	identity, err := resolveInstallIdentity(map[string]bool{}, "", "", "", "auto", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if identity.ServiceName != "custom-lg" {
		t.Fatalf("service name = %q, want custom-lg", identity.ServiceName)
	}

	// The same recovery works for OpenRC init scripts.
	if err := os.Remove(filepath.Join(systemdUnitDir, "custom-lg.service")); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf("command=\"%s\"\ncommand_args=\"--config %s\"\n", exe, filepath.Join(installDir, "agent.json"))
	if err := os.WriteFile(filepath.Join(openrcInitDir, "custom-lg"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	identity, err = resolveInstallIdentity(map[string]bool{}, "", "", "", "auto", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if identity.ServiceName != "custom-lg" {
		t.Fatalf("init.d service name = %q, want custom-lg", identity.ServiceName)
	}
}

// Uninstall must refuse to act when the resolved target is a different binary
// from the one running — that is how a default-named uninstall could tear down
// the wrong installation.
func TestRunUninstallRefusesWithoutRecordedConfig(t *testing.T) {
	installDir := filepath.Join(t.TempDir(), "srv", "lg")
	dataDir := filepath.Join(installDir, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(installDir, "hlg-agent")
	if err := os.WriteFile(binaryPath, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	// No agent.json and no explicit target: the tool must refuse rather than
	// guess defaults and delete a possibly-unrelated install.
	identity := installIdentity{
		InstallDir:  installDir,
		DataDir:     dataDir,
		BinaryName:  "hlg-agent",
		ServiceName: "hlg-agent",
		ServiceMode: "none",
	}
	if err := runUninstall(identity); err == nil {
		t.Fatal("expected a refusal when no agent.json is present")
	}
	if !fileExists(binaryPath) || !fileExists(dataDir) {
		t.Fatal("nothing must be deleted when the target is unconfirmed")
	}
	// An explicit target is intentional and must proceed.
	identity.ExplicitTarget = true
	if err := runUninstall(identity); err != nil {
		t.Fatalf("explicit target should uninstall: %v", err)
	}
	if fileExists(binaryPath) {
		t.Fatal("binary not removed after explicit confirmation")
	}
}

func TestRunUninstallRefusesForeignTarget(t *testing.T) {
	installDir := filepath.Join(t.TempDir(), "srv", "lg")
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(installDir, "my-agent")
	if err := os.WriteFile(binaryPath, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	stubExecutable(t, filepath.Join(t.TempDir(), "elsewhere", "other-agent"))

	identity := installIdentity{
		InstallDir:  installDir,
		DataDir:     filepath.Join(installDir, "data"),
		BinaryName:  "my-agent",
		ServiceName: "my-agent",
		ServiceMode: "none",
	}
	if err := runUninstall(identity); err == nil {
		t.Fatal("expected a mismatch error when the running binary is not the target")
	}

	// An explicitly confirmed target is intentional and must proceed.
	identity.ExplicitTarget = true
	if err := runUninstall(identity); err != nil {
		t.Fatalf("explicit target should uninstall: %v", err)
	}
	if fileExists(binaryPath) {
		t.Fatal("binary not removed")
	}
	if fileExists(installDir) {
		t.Fatal("empty install dir not removed")
	}
}

// Uninstall must follow the recorded service fields: the custom unit is removed
// and the recorded data dir is wiped, while unrelated files survive.
func TestRunUninstallRemovesRecordedLayout(t *testing.T) {
	base := t.TempDir()
	installDir := filepath.Join(base, "srv", "lg")
	dataDir := filepath.Join(base, "var", "lg-data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(installDir, "my-agent")
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	record := map[string]any{
		"install_dir":  installDir,
		"binary_name":  "my-agent",
		"service_name": "my-agent-svc",
		"service_mode": "systemd",
		"data_dir":     dataDir,
	}
	body, _ := json.Marshal(record)
	if err := os.WriteFile(filepath.Join(installDir, "agent.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	stubExecutable(t, exe)
	// The unit the install created, in the stubbed systemd dir.
	unit := fmt.Sprintf("[Service]\nExecStart=%s --config %s\n", exe, filepath.Join(installDir, "agent.json"))
	unitPath := filepath.Join(systemdUnitDir, "my-agent-svc.service")
	if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
		t.Fatal(err)
	}
	// An unrelated file in the install dir must survive the uninstall.
	if err := os.WriteFile(filepath.Join(installDir, "README"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}

	identity, err := resolveInstallIdentity(map[string]bool{}, "", "", "", "auto", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if identity.ServiceName != "my-agent-svc" || identity.ServiceMode != "systemd" || identity.DataDir != dataDir {
		t.Fatalf("identity = %+v", identity)
	}
	if err := runUninstall(identity); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if fileExists(unitPath) {
		t.Fatal("custom service unit not removed")
	}
	if fileExists(exe) || fileExists(filepath.Join(installDir, "agent.json")) {
		t.Fatal("install files not removed")
	}
	if fileExists(dataDir) {
		t.Fatal("recorded data dir not removed")
	}
	if !fileExists(filepath.Join(installDir, "README")) {
		t.Fatal("unrelated file in the install dir was removed")
	}
}

// --install must copy the running binary into the install dir when it was
// invoked from elsewhere, so a download-and-install in one step works.
func TestRunInstallCopiesBinaryFromExecPath(t *testing.T) {
	stubInstallDeps(t)
	stubInstallPortProbe(t)
	base := t.TempDir()
	exe := filepath.Join(base, "downloaded-hlg-agent")
	if err := os.WriteFile(exe, []byte("fake-binary-content"), 0o755); err != nil {
		t.Fatal(err)
	}
	stubExecutable(t, exe)

	installDir := filepath.Join(base, "opt", "lg")
	dataDir := filepath.Join(installDir, "data")
	if err := runInstall("", installDir, dataDir, "none", "root", "hlg-agent", "hlg-agent", "https://lg.example", "", "", "", "", "", "", false); err != nil {
		t.Fatal(err)
	}
	installed, err := os.ReadFile(filepath.Join(installDir, "hlg-agent"))
	if err != nil {
		t.Fatal(err)
	}
	if string(installed) != "fake-binary-content" {
		t.Fatalf("installed binary content = %q", installed)
	}

	// The recorded layout must name the real install dir/binary/service.
	var runtimeCfg map[string]any
	runtimeBody, err := os.ReadFile(filepath.Join(installDir, "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(runtimeBody, &runtimeCfg); err != nil {
		t.Fatal(err)
	}
	if runtimeCfg["install_dir"] != installDir || runtimeCfg["binary_name"] != "hlg-agent" || runtimeCfg["service_name"] != "hlg-agent" || runtimeCfg["service_mode"] != "none" {
		t.Fatalf("install layout not recorded: %#v", runtimeCfg)
	}
}

func TestSyncRunnerReportsConfigPullFailure(t *testing.T) {
	// The public-IP probe would otherwise reach api4/api6.ipify.org; stub it so
	// the test is hermetic and fast.
	restore := publicIPClient
	publicIPClient = &http.Client{Transport: failingTransport{}}
	t.Cleanup(func() { publicIPClient = restore })

	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The controller is unreachable for config: report a 500 so the pull
		// fails. This is what the reload trigger must surface as a failure.
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer controller.Close()

	cfg := config.Defaults()
	cfg.Controller = controller.URL
	cfg.NodeToken = "lgnode_test"
	cfg.NodeID = "edge01"
	runner := newSyncRunner(cfg, &config.SignedBundle{NodeID: "edge01"}, certstore.New(t.TempDir()), &publicIPState{})

	if err := runner.run(context.Background()); err == nil {
		t.Fatal("expected a sync error when the config pull fails")
	}
}

func TestRefreshPublicIPsPreservesExplicitAddressAndRefreshesOtherFamily(t *testing.T) {
	var ipv4Requests, ipv6Requests int
	previous := publicIPClient
	publicIPClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body := ""
		switch req.URL.Host {
		case "api4.ipify.org":
			ipv4Requests++
			body = "198.51.100.8"
		case "api6.ipify.org":
			ipv6Requests++
			body = "2001:db8::8"
		default:
			t.Fatalf("unexpected public IP endpoint: %s", req.URL)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	t.Cleanup(func() { publicIPClient = previous })

	cfg := config.Config{PublicIPv4: "203.0.113.7"}
	state := newPublicIPState(cfg)
	refreshPublicIPs(context.Background(), &cfg, state)
	if cfg.PublicIPv4 != "203.0.113.7" || state.IPv4() != "203.0.113.7" {
		t.Fatalf("explicit IPv4 override changed: config=%q state=%q", cfg.PublicIPv4, state.IPv4())
	}
	if cfg.PublicIPv6 != "2001:db8::8" || state.IPv6() != "2001:db8::8" {
		t.Fatalf("IPv6 discovery not applied: config=%q state=%q", cfg.PublicIPv6, state.IPv6())
	}
	if ipv4Requests != 0 || ipv6Requests != 1 {
		t.Fatalf("probe counts = IPv4 %d, IPv6 %d; want 0 and 1", ipv4Requests, ipv6Requests)
	}

	// Controller state refreshes must not erase local overrides.
	state.set("198.51.100.9", "2001:db8::9")
	if state.IPv4() != "203.0.113.7" {
		t.Fatalf("controller IPv4 replaced local override: %q", state.IPv4())
	}

	// A non-empty address learned from a signed bundle is not a local override;
	// periodic refresh must still detect changes to dynamic addresses.
	dynamicCfg := config.Config{PublicIPv6: "2001:db8::7"}
	dynamicState := &publicIPState{}
	refreshPublicIPs(context.Background(), &dynamicCfg, dynamicState)
	if dynamicCfg.PublicIPv6 != "2001:db8::8" || dynamicState.IPv6() != "2001:db8::8" {
		t.Fatalf("dynamic IPv6 was not refreshed: config=%q state=%q", dynamicCfg.PublicIPv6, dynamicState.IPv6())
	}
	if ipv4Requests != 1 || ipv6Requests != 2 {
		t.Fatalf("after dynamic refresh, probe counts = IPv4 %d, IPv6 %d; want 1 and 2", ipv4Requests, ipv6Requests)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestPullCertificateBundleTreatsNoPendingBundleAsSuccess(t *testing.T) {
	// A 404 on the cert bundle is the healthy steady state (nothing pending),
	// so the reload trigger must not report it as a failure.
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer controller.Close()

	cfg := config.Defaults()
	cfg.Controller = controller.URL
	cfg.NodeToken = "lgnode_test"
	cfg.NodeID = "edge01"
	active := &config.SignedBundle{NodeID: "edge01"}
	bundle, err := pullCertificateBundle(context.Background(), cfg, active, certstore.New(t.TempDir()), enroll.NewClient(cfg))
	if err != nil {
		t.Fatalf("no pending certificate bundle must not be an error: %v", err)
	}
	if bundle != active {
		t.Fatal("the active bundle must be preserved when none is pending")
	}
}

// failingTransport makes the public-IP probe fail immediately without touching
// the network.
type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("no network in tests")
}
