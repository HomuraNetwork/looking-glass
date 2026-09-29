package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	Controller       string          `json:"controller"`
	EnrollToken      string          `json:"enroll_token"`
	InitToken        string          `json:"init_token"`
	InitString       string          `json:"init_string,omitempty"`
	NodeToken        string          `json:"node_token"`
	NodeID           string          `json:"node_id"`
	Bind             string          `json:"bind"`
	DataDir          string          `json:"data_dir"`
	Domain           string          `json:"domain"`
	PublicIPv4       string          `json:"public_ipv4"`
	PublicIPv6       string          `json:"public_ipv6"`
	DynamicIP        bool            `json:"dynamic_ip"`
	Features         map[string]bool `json:"features"`
	Limits           Limits          `json:"limits"`
	RemoteBundle     *SignedBundle   `json:"remote_bundle,omitempty"`
	ConfigFile       string          `json:"-"`
	FrontendOrigin   string          `json:"frontend_origin"`
	IperfDebugOutput bool            `json:"iperf_debug_output"`
	// Tools records the resolved absolute path of each runtime tool, written at
	// install time so the runtime invokes a known binary instead of searching
	// PATH on every call. Missing entries fall back to PATH.
	Tools map[string]string `json:"tools,omitempty"`
	// LogLevel is one of debug, info, warn, error (default info).
	LogLevel string `json:"log_level"`
	// LogFile redirects logs to a file; empty means stdout (systemd/journal
	// or logread).
	LogFile string `json:"log_file"`
	// SyncIntervalHealthySeconds is the periodic controller-sync cadence once a
	// valid managed certificate is in place. Config/cert changes are pushed via
	// reload requests, so this is mainly an uptime/reconciliation safety net;
	// 0 falls back to 45 minutes.
	SyncIntervalHealthySeconds int `json:"sync_interval_healthy_seconds"`
}

type LoadOptions struct {
	File   string
	Flags  map[string]string
	Bundle *SignedBundle
}

func Load(opts LoadOptions) (Config, error) {
	cfg := Defaults()

	if opts.Bundle != nil {
		mergeBundle(&cfg, opts.Bundle)
	}
	if opts.File == "" {
		dataDir := resolveDataDir(cfg.DataDir, opts.Flags)
		if dataDir != "" {
			defaultPath := filepath.Join(dataDir, "config.json")
			fileCfg, err := loadFile(defaultPath)
			if err != nil {
				return Config{}, err
			}
			mergeConfig(&cfg, fileCfg)
			cfg.ConfigFile = defaultPath
		}
	}
	if opts.File != "" {
		fileCfg, err := loadFile(opts.File)
		if err != nil {
			return Config{}, err
		}
		mergeConfig(&cfg, fileCfg)
		cfg.ConfigFile = opts.File
	}
	applyEnv(&cfg)
	applyFlags(&cfg, opts.Flags)

	return cfg, nil
}

func resolveDataDir(fallback string, flags map[string]string) string {
	if flags != nil {
		if value := strings.TrimSpace(flags["data-dir"]); value != "" {
			return value
		}
	}
	if value := strings.TrimSpace(os.Getenv("LG_DATA_DIR")); value != "" {
		return value
	}
	return fallback
}

func loadFile(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Config{}, nil
		}
		return Config{}, err
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func mergeBundle(cfg *Config, bundle *SignedBundle) {
	if bundle.NodeID != "" {
		cfg.NodeID = bundle.NodeID
	}
	if bundle.Domain != "" {
		cfg.Domain = bundle.Domain
	}
	if bundle.PublicIPv4 != "" {
		cfg.PublicIPv4 = bundle.PublicIPv4
	}
	if bundle.PublicIPv6 != "" {
		cfg.PublicIPv6 = bundle.PublicIPv6
	}
	cfg.DynamicIP = bundle.DynamicIP
	if bundle.Features != nil {
		cfg.Features = cloneBoolMap(bundle.Features)
	}
	cfg.Limits = mergeLimits(cfg.Limits, bundle.Limits)
	cfg.RemoteBundle = bundle
}

func mergeConfig(dst *Config, src Config) {
	if src.Controller != "" {
		dst.Controller = src.Controller
	}
	if src.EnrollToken != "" {
		dst.EnrollToken = src.EnrollToken
	}
	if src.InitToken != "" {
		dst.InitToken = src.InitToken
	}
	if src.NodeToken != "" {
		dst.NodeToken = src.NodeToken
	}
	if src.NodeID != "" {
		dst.NodeID = src.NodeID
	}
	if src.Bind != "" {
		dst.Bind = src.Bind
	}
	if src.DataDir != "" {
		dst.DataDir = src.DataDir
	}
	if src.PublicIPv4 != "" {
		dst.PublicIPv4 = src.PublicIPv4
	}
	if src.PublicIPv6 != "" {
		dst.PublicIPv6 = src.PublicIPv6
	}
	if src.Features != nil {
		dst.Features = cloneBoolMap(src.Features)
	}
	if src.Tools != nil {
		dst.Tools = cloneStringMap(src.Tools)
	}
	dst.Limits = mergeLimits(dst.Limits, src.Limits)
	if src.RemoteBundle != nil && dst.RemoteBundle == nil {
		dst.RemoteBundle = src.RemoteBundle
	}
	if src.FrontendOrigin != "" {
		dst.FrontendOrigin = src.FrontendOrigin
	}
	if src.IperfDebugOutput {
		dst.IperfDebugOutput = true
	}
	if src.LogLevel != "" {
		dst.LogLevel = src.LogLevel
	}
	if src.LogFile != "" {
		dst.LogFile = src.LogFile
	}
	if src.SyncIntervalHealthySeconds != 0 {
		dst.SyncIntervalHealthySeconds = src.SyncIntervalHealthySeconds
	}
}

func applyEnv(cfg *Config) {
	envString("LG_CONTROLLER", &cfg.Controller)
	envString("LG_ENROLL_TOKEN", &cfg.EnrollToken)
	envString("LG_INIT_TOKEN", &cfg.InitToken)
	envString("LG_INIT_STRING", &cfg.InitString)
	envString("LG_NODE_TOKEN", &cfg.NodeToken)
	envString("LG_NODE_ID", &cfg.NodeID)
	envString("LG_BIND", &cfg.Bind)
	envString("LG_DATA_DIR", &cfg.DataDir)
	envString("LG_PUBLIC_IPV4", &cfg.PublicIPv4)
	envString("LG_PUBLIC_IPV6", &cfg.PublicIPv6)
	envString("LG_FRONTEND_ORIGIN", &cfg.FrontendOrigin)
	envBool("LG_IPERF_DEBUG_OUTPUT", &cfg.IperfDebugOutput)
	envString("LG_LOG_LEVEL", &cfg.LogLevel)
	envString("LG_LOG_FILE", &cfg.LogFile)
	envInt("LG_SYNC_INTERVAL_HEALTHY_SECONDS", &cfg.SyncIntervalHealthySeconds)
}

func applyFlags(cfg *Config, flags map[string]string) {
	if flags == nil {
		return
	}
	for key, value := range flags {
		if value == "" {
			continue
		}
		switch key {
		case "controller":
			cfg.Controller = value
		case "enroll-token":
			cfg.EnrollToken = value
		case "init-token":
			cfg.InitToken = value
		case "init-string":
			cfg.InitString = value
		case "node-token":
			cfg.NodeToken = value
		case "node-id":
			cfg.NodeID = value
		case "bind":
			cfg.Bind = value
		case "data-dir":
			cfg.DataDir = value
		case "public-ipv4":
			cfg.PublicIPv4 = value
		case "public-ipv6":
			cfg.PublicIPv6 = value
		case "frontend-origin":
			cfg.FrontendOrigin = value
		case "iperf-debug-output":
			cfg.IperfDebugOutput = parseBool(value)
		case "log-level":
			cfg.LogLevel = value
		case "log-file":
			cfg.LogFile = value
		}
	}
}

func envString(name string, target *string) {
	if value := os.Getenv(name); value != "" {
		*target = value
	}
}

func envBool(name string, target *bool) {
	if value := os.Getenv(name); value != "" {
		*target = parseBool(value)
	}
}

func envInt(name string, target *int) {
	if value := os.Getenv(name); value != "" {
		if parsed, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
			*target = parsed
		}
	}
}

func parseBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func cloneBoolMap(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func cloneStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func mergeLimits(dst, src Limits) Limits {
	if src.DownloadConcurrency != 0 {
		dst.DownloadConcurrency = src.DownloadConcurrency
	}
	if src.DownloadMaxRequestsPerToken != 0 {
		dst.DownloadMaxRequestsPerToken = src.DownloadMaxRequestsPerToken
	}
	if src.DownloadMaxBytesMultiplier != 0 {
		dst.DownloadMaxBytesMultiplier = src.DownloadMaxBytesMultiplier
	}
	if src.IperfActiveSessions != 0 {
		dst.IperfActiveSessions = src.IperfActiveSessions
	}
	if src.JobConcurrencyPerIP != 0 {
		dst.JobConcurrencyPerIP = src.JobConcurrencyPerIP
	}
	if src.JobTimeoutSec != 0 {
		dst.JobTimeoutSec = src.JobTimeoutSec
	}
	if src.JobMaxOutputBytes != 0 {
		dst.JobMaxOutputBytes = src.JobMaxOutputBytes
	}
	if len(src.AllowedDownloadSizes) > 0 {
		dst.AllowedDownloadSizes = append([]string(nil), src.AllowedDownloadSizes...)
	}
	if src.IperfPortMin != 0 {
		dst.IperfPortMin = src.IperfPortMin
	}
	if src.IperfPortMax != 0 {
		dst.IperfPortMax = src.IperfPortMax
	}
	if src.IperfTTLSeconds != 0 {
		dst.IperfTTLSeconds = src.IperfTTLSeconds
	}
	if src.IperfMaxDuration != 0 {
		dst.IperfMaxDuration = src.IperfMaxDuration
	}
	if src.IperfMaxParallel != 0 {
		dst.IperfMaxParallel = src.IperfMaxParallel
	}
	if src.IperfMaxRuns != 0 {
		dst.IperfMaxRuns = src.IperfMaxRuns
	}
	if src.IperfRunBudget != 0 {
		dst.IperfRunBudget = src.IperfRunBudget
	}
	if src.TokenIPv4Prefix != 0 {
		dst.TokenIPv4Prefix = src.TokenIPv4Prefix
	}
	if src.TokenIPv6Prefix != 0 {
		dst.TokenIPv6Prefix = src.TokenIPv6Prefix
	}
	if src.AllowedControlTTL != 0 {
		dst.AllowedControlTTL = src.AllowedControlTTL
	}
	if src.GuardPrivateIP != nil {
		dst.GuardPrivateIP = src.GuardPrivateIP
	}
	return dst
}
