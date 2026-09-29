package config

type SignedBundle struct {
	Version    int64           `json:"version"`
	NodeID     string          `json:"node_id"`
	Domain     string          `json:"domain"`
	PublicIPv4 string          `json:"public_ipv4,omitempty"`
	PublicIPv6 string          `json:"public_ipv6,omitempty"`
	DynamicIP  bool            `json:"dynamic_ip,omitempty"`
	IssuedAt   int64           `json:"issued_at"`
	ExpiresAt  int64           `json:"expires_at"`
	Features   map[string]bool `json:"features"`
	Limits     Limits          `json:"limits"`
	ConfigKID  string          `json:"config_kid"`
	Keyset     []Key           `json:"keyset"`
	Signature  string          `json:"signature"`
}

type Key struct {
	KID       string `json:"kid"`
	Alg       string `json:"alg"`
	Use       string `json:"use"`
	PublicKey string `json:"public_key"`
}

type Limits struct {
	DownloadConcurrency         int      `json:"download_concurrency"`
	DownloadMaxRequestsPerToken int      `json:"download_max_requests_per_token"`
	DownloadMaxBytesMultiplier  int      `json:"download_max_bytes_multiplier"`
	IperfActiveSessions         int      `json:"iperf_active_sessions"`
	JobConcurrencyPerIP         int      `json:"job_concurrency_per_ip"`
	JobTimeoutSec               int      `json:"job_timeout_sec"`
	JobMaxOutputBytes           int      `json:"job_max_output_bytes"`
	AllowedDownloadSizes        []string `json:"allowed_download_sizes"`
	IperfPortMin                int      `json:"iperf_port_min"`
	IperfPortMax                int      `json:"iperf_port_max"`
	IperfTTLSeconds             int      `json:"iperf_ttl_seconds"`
	IperfMaxDuration            int      `json:"iperf_max_duration"`
	IperfMaxParallel            int      `json:"iperf_max_parallel"`
	IperfMaxRuns                int      `json:"iperf_max_runs"`
	IperfRunBudget              int      `json:"iperf_run_budget"`
	TokenIPv4Prefix             int      `json:"token_ipv4_prefix"`
	TokenIPv6Prefix             int      `json:"token_ipv6_prefix"`
	AllowedControlTTL           int      `json:"allowed_control_ttl"`
	// GuardPrivateIP toggles the agent-side execute-time private-IP
	// guard; nil/omitted keeps the default (true). Exposed as a pointer
	// so bundles can explicitly disable the guard (operator escape
	// hatch; the worker-side check remains regardless).
	GuardPrivateIP *bool `json:"guard_private_ip,omitempty"`
}
