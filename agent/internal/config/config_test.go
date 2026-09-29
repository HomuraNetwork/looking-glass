package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAppliesDefaultsEnvFileAndFlagsInPriorityOrder(t *testing.T) {
	t.Setenv("LG_CONTROLLER", "https://env-controller.example")
	t.Setenv("LG_ENROLL_TOKEN", "env-token")
	t.Setenv("LG_BIND", ":9443")
	t.Setenv("LG_DATA_DIR", "/tmp/env-data")

	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	if err := os.WriteFile(path, []byte(`{
		"controller": "https://file-controller.example",
		"enroll_token": "file-token",
		"node_id": "file-node",
		"bind": ":7443",
		"data_dir": "/tmp/file-data"
	}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(LoadOptions{
		File: path,
		Flags: map[string]string{
			"bind": ":8443",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Controller != "https://env-controller.example" {
		t.Fatalf("controller = %q", cfg.Controller)
	}
	if cfg.EnrollToken != "env-token" {
		t.Fatalf("enroll token = %q", cfg.EnrollToken)
	}
	if cfg.NodeID != "file-node" {
		t.Fatalf("node id = %q", cfg.NodeID)
	}
	if cfg.Bind != ":8443" {
		t.Fatalf("bind = %q", cfg.Bind)
	}
	if cfg.DataDir != "/tmp/env-data" {
		t.Fatalf("data dir = %q", cfg.DataDir)
	}
}

func TestLoadAppliesSignedBundleBelowFileEnvAndFlags(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	if err := os.WriteFile(path, []byte(`{
		"remote_bundle": {
			"version": 9,
			"node_id": "cached-node",
			"domain": "cached.example",
			"features": {"download": true},
			"limits": {"iperf_max_runs": 3},
			"config_kid": "cached-config",
			"keyset": [],
			"signature": "cached-signature"
		}
	}`), 0o600); err != nil {
		t.Fatal(err)
	}

	bundle := SignedBundle{
		Version:  12,
		NodeID:   "bundle-node",
		Domain:   "bundle.example",
		Features: map[string]bool{"download": true, "iperf3": true},
		Limits:   Limits{IperfMaxRuns: 4, IperfRunBudget: 200},
		Keyset:   []Key{{KID: "token", Alg: "Ed25519", Use: "token_verify", PublicKey: "abc"}},
	}

	cfg, err := Load(LoadOptions{
		File:   path,
		Bundle: &bundle,
		Flags:  map[string]string{"node-id": "flag-node"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if cfg.NodeID != "flag-node" || cfg.Domain != "bundle.example" {
		t.Fatalf("priority not preserved: %#v", cfg)
	}
	if !cfg.Features["iperf3"] || cfg.Limits.IperfMaxRuns != 4 {
		t.Fatalf("bundle runtime config not applied: %#v", cfg)
	}
	if cfg.RemoteBundle == nil || cfg.RemoteBundle.NodeID != "bundle-node" {
		t.Fatalf("fresh remote bundle not preserved: %#v", cfg.RemoteBundle)
	}
}

func TestLoadReadsCachedRemoteBundleFromConfigFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	if err := os.WriteFile(path, []byte(`{
		"remote_bundle": {
			"version": 9,
			"node_id": "cached-node",
			"domain": "cached.example",
			"features": {"download": true},
			"limits": {"iperf_max_runs": 3},
			"config_kid": "cached-config",
			"keyset": [],
			"signature": "cached-signature"
		}
	}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(LoadOptions{File: path})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RemoteBundle == nil || cfg.RemoteBundle.NodeID != "cached-node" {
		t.Fatalf("cached remote bundle not loaded: %#v", cfg.RemoteBundle)
	}
}

func TestDefaultsAllowTenConcurrentIperfSessions(t *testing.T) {
	cfg := Defaults()
	if cfg.Limits.IperfActiveSessions != 10 {
		t.Fatalf("iperf active sessions = %d, want 10", cfg.Limits.IperfActiveSessions)
	}
	if cfg.Limits.IperfMaxRuns != 4 {
		t.Fatalf("iperf max runs = %d, want 4", cfg.Limits.IperfMaxRuns)
	}
	if cfg.Limits.IperfRunBudget != 200 {
		t.Fatalf("iperf run budget = %d, want 200", cfg.Limits.IperfRunBudget)
	}
}

func TestMergeLimitsAppliesDownloadBudgetOverrides(t *testing.T) {
	base := Defaults()
	merged := mergeLimits(base.Limits, Limits{
		DownloadMaxRequestsPerToken: 8,
		DownloadMaxBytesMultiplier:  6,
	})
	if merged.DownloadMaxRequestsPerToken != 8 {
		t.Fatalf("requests per token = %d, want 8", merged.DownloadMaxRequestsPerToken)
	}
	if merged.DownloadMaxBytesMultiplier != 6 {
		t.Fatalf("bytes multiplier = %d, want 6", merged.DownloadMaxBytesMultiplier)
	}

	// Zero values in src must preserve dst values.
	untouched := mergeLimits(base.Limits, Limits{})
	if untouched.DownloadMaxRequestsPerToken != 12 {
		t.Fatalf("requests per token should default to 12, got %d", untouched.DownloadMaxRequestsPerToken)
	}
	if untouched.DownloadMaxBytesMultiplier != 4 {
		t.Fatalf("bytes multiplier should default to 4, got %d", untouched.DownloadMaxBytesMultiplier)
	}
}

func TestMergeLimitsGuardPrivateIPOverrides(t *testing.T) {
	base := Defaults()
	if base.Limits.GuardPrivateIP != nil {
		t.Fatalf("defaults should leave GuardPrivateIP nil (runner default true), got %v", *base.Limits.GuardPrivateIP)
	}
	disabled := false
	merged := mergeLimits(base.Limits, Limits{GuardPrivateIP: &disabled})
	if merged.GuardPrivateIP == nil || *merged.GuardPrivateIP {
		t.Fatalf("explicit false should override, got %#v", merged.GuardPrivateIP)
	}
	// Nil src must preserve dst value.
	if mergeLimits(merged, Limits{}).GuardPrivateIP == nil {
		t.Fatal("nil src should preserve the dst pointer")
	}
	enabled := true
	if *mergeLimits(base.Limits, Limits{GuardPrivateIP: &enabled}).GuardPrivateIP != true {
		t.Fatal("explicit true should be honored")
	}
}

func TestConfigEnablesIperfDebugOutputFromEnv(t *testing.T) {
	t.Setenv("LG_IPERF_DEBUG_OUTPUT", "true")
	cfg, err := Load(LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.IperfDebugOutput {
		t.Fatal("expected iperf debug output to be enabled")
	}
}
