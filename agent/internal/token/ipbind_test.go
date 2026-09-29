package token

import "testing"

// A token minted for an IPv4 address must still bind when the peer address
// arrives in IPv4-mapped IPv6 form (::ffff:a.b.c.d), which Linux/Go can report
// for dual-stack sockets. The reverse must hold too.
func TestIPAllowedNormalizesIPv4MappedIPv6(t *testing.T) {
	cases := []struct {
		name     string
		policy   string
		tokenIP  string
		clientIP string
		want     bool
	}{
		{"relaxed mapped client", "relaxed", "203.0.113.10", "::ffff:203.0.113.10", true},
		{"relaxed mapped token", "relaxed", "::ffff:203.0.113.10", "203.0.113.10", true},
		{"strict mapped client", "strict", "203.0.113.10", "::ffff:203.0.113.10", true},
		{"strict mapped token", "strict", "::ffff:203.0.113.10", "203.0.113.10", true},
		{"relaxed outside prefix", "relaxed", "203.0.113.10", "198.51.100.10", false},
		{"strict different address", "strict", "203.0.113.10", "203.0.113.11", false},
		{"relaxed v6", "relaxed", "2001:db8::1", "2001:db8::2", true},
		{"family mismatch", "relaxed", "203.0.113.10", "2001:db8::1", false},
		{"none always allows", "none", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ipAllowed(tc.policy, tc.tokenIP, tc.clientIP, 24, 48); got != tc.want {
				t.Fatalf("ipAllowed(%q, %q, %q) = %t, want %t", tc.policy, tc.tokenIP, tc.clientIP, got, tc.want)
			}
		})
	}
}
