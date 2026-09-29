package config

const (
	DefaultBind    = ":443"
	DefaultDataDir = "/opt/looking-glass/data"
)

func Defaults() Config {
	return Config{
		Bind:    DefaultBind,
		DataDir: DefaultDataDir,
		Features: map[string]bool{
			"generate204": true,
			"download":    true,
			"ping":        true,
			"mtr":         true,
			"traceroute":  true,
			"nexttrace":   true,
			"iperf3":      true,
		},
		Limits: Limits{
			DownloadConcurrency:         2,
			DownloadMaxRequestsPerToken: 12,
			DownloadMaxBytesMultiplier:  4,
			IperfActiveSessions:         10,
			JobConcurrencyPerIP:         1,
			JobTimeoutSec:               45,
			JobMaxOutputBytes:           65536,
			AllowedDownloadSizes: []string{
				"10M",
				"100M",
				"1G",
			},
			IperfPortMin:      30000,
			IperfPortMax:      39999,
			IperfTTLSeconds:   180,
			IperfMaxDuration:  40,
			IperfMaxParallel:  10,
			IperfMaxRuns:      4,
			IperfRunBudget:    200,
			TokenIPv4Prefix:   24,
			TokenIPv6Prefix:   48,
			AllowedControlTTL: 300,
		},
	}
}
