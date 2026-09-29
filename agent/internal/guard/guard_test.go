package guard

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestCheckMatchesCanonicalBlocklist(t *testing.T) {
	blocked := []string{
		// IPv4
		"0.0.0.0",
		"0.1.2.3",
		"10.1.2.3",
		"100.64.0.1",
		"100.127.255.254",
		"127.0.0.1",
		"169.254.0.1",
		"172.16.0.1",
		"172.31.255.255",
		"192.0.0.5",
		"192.0.0.255",
		"192.168.1.20",
		"198.18.0.1",
		"198.19.255.255",
		"224.0.0.1",
		"239.1.2.3",
		"240.0.0.1",
		"255.255.255.255",
		// IPv6
		"::",
		"::1",
		"fc00::1",
		"fd12:3456::1",
		"fe80::1",
		"ff02::1",
		// IPv4-mapped IPv6 (dotted and hex forms)
		"::ffff:10.0.0.1",
		"::ffff:127.0.0.1",
		"::ffff:192.168.0.1",
		"::ffff:c0a8:0001",
		"::ffff:0a00:0001",
	}
	for _, ip := range blocked {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			t.Fatalf("test vector %q is not a valid IP", ip)
		}
		if !Check(parsed) {
			t.Errorf("Check(%q) = false, want blocked", ip)
		}
	}

	allowed := []string{
		"1.1.1.1",
		"8.8.8.8",
		"203.0.113.9",
		"198.20.0.1", // just outside the benchmarking range
		"198.51.100.10",
		"203.0.113.10",
		"100.128.0.1", // just above CGNAT
		"172.32.0.1",  // just above private range
		"2001:db8::1", // documentation range, not in scope
		"2606:4700:4700::1111",
		"2606:4700:4700::1001",
		"::ffff:8.8.8.8",
	}
	for _, ip := range allowed {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			t.Fatalf("test vector %q is not a valid IP", ip)
		}
		if Check(parsed) {
			t.Errorf("Check(%q) = true, want allowed", ip)
		}
	}
}

func TestCheckNilIPFailsClosed(t *testing.T) {
	if !Check(nil) {
		t.Fatal("Check(nil) = false, want blocked (fail closed)")
	}
}

func TestCheckHostBlocksLiteralPrivateIP(t *testing.T) {
	err := CheckHost(context.Background(), "10.0.0.8", nil)
	if !errors.Is(err, ErrBlockedPrivateIP) {
		t.Fatalf("err = %v, want ErrBlockedPrivateIP", err)
	}
	if !contains(err.Error(), "10.0.0.8") {
		t.Fatalf("error text should include the blocked IP: %q", err.Error())
	}
}

func TestCheckHostAllowsLiteralPublicIP(t *testing.T) {
	if err := CheckHost(context.Background(), "1.1.1.1", nil); err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
}

func TestCheckHostBlocksAnyResolvedPrivateIP(t *testing.T) {
	resolve := func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("192.168.0.1")}, nil
	}
	err := CheckHost(context.Background(), "mixed.example", resolve)
	if !errors.Is(err, ErrBlockedPrivateIP) {
		t.Fatalf("err = %v, want ErrBlockedPrivateIP", err)
	}
	if !contains(err.Error(), "192.168.0.1") {
		t.Fatalf("error text should include the blocked IP: %q", err.Error())
	}
}

func TestCheckHostAllowsAllPublicResolvedIPs(t *testing.T) {
	resolve := func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("2606:4700:4700::1111")}, nil
	}
	if err := CheckHost(context.Background(), "public.example", resolve); err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
}

func TestResolveHostSelectsRequestedFamilyAfterValidatingAllRecords(t *testing.T) {
	resolve := func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("2606:4700:4700::1111"), net.ParseIP("1.1.1.1")}, nil
	}
	ip, err := ResolveHost(context.Background(), "dual.example", resolve, "ipv4")
	if err != nil {
		t.Fatal(err)
	}
	if got := ip.String(); got != "1.1.1.1" {
		t.Fatalf("selected IP = %s, want 1.1.1.1", got)
	}
}

func TestResolveHostRejectsPrivateRecordBeforeSelectingPublicFamily(t *testing.T) {
	resolve := func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("192.168.1.2")}, nil
	}
	_, err := ResolveHost(context.Background(), "mixed.example", resolve, "ipv4")
	if !errors.Is(err, ErrBlockedPrivateIP) {
		t.Fatalf("err = %v, want ErrBlockedPrivateIP", err)
	}
}

func TestCheckHostFailsClosedOnResolveError(t *testing.T) {
	resolve := func(context.Context, string) ([]net.IP, error) {
		return nil, errors.New("dns timeout")
	}
	err := CheckHost(context.Background(), "unreachable.example", resolve)
	if !errors.Is(err, ErrTargetResolveFailed) {
		t.Fatalf("err = %v, want ErrTargetResolveFailed", err)
	}
}

func TestCheckHostFailsClosedOnEmptyRecords(t *testing.T) {
	resolve := func(context.Context, string) ([]net.IP, error) {
		return nil, nil
	}
	err := CheckHost(context.Background(), "empty.example", resolve)
	if !errors.Is(err, ErrTargetResolveFailed) {
		t.Fatalf("err = %v, want ErrTargetResolveFailed", err)
	}
}

func TestCheckHostFailsClosedOnEmptyTarget(t *testing.T) {
	err := CheckHost(context.Background(), "   ", nil)
	if !errors.Is(err, ErrTargetResolveFailed) {
		t.Fatalf("err = %v, want ErrTargetResolveFailed", err)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
