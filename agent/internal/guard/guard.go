// Package guard implements the execute-time private/reserved IP guard for
// job targets. The worker resolves DNS and applies the same blocklist
// before issuing a job token, but the token only carries the domain, so
// the agent re-resolves the target at execution time and re-checks it
// here (defense in depth against DNS rebinding between token issuance
// and execution).
//
// Canonical blocklist — MUST stay in sync with controller/src/ip-guard.ts
// (isPrivateIPAddress). There is no shared package between the worker
// (TypeScript) and the agent (Go), so both ends duplicate this list;
// update both whenever a range is added or removed.
//
// IPv4:
//
//	0.0.0.0/8        "this network"
//	10.0.0.0/8       private
//	100.64.0.0/10    CGNAT shared address space
//	127.0.0.0/8      loopback
//	169.254.0.0/16   link-local
//	172.16.0.0/12    private
//	192.0.0.0/24     IETF protocol assignments
//	192.168.0.0/16   private
//	198.18.0.0/15    benchmarking
//	224.0.0.0/4      multicast
//	240.0.0.0/4      reserved (includes 255.255.255.255 broadcast)
//
// IPv6:
//
//	::/128           unspecified
//	::1/128          loopback
//	fc00::/7         unique local
//	fe80::/10        link-local
//	ff00::/8         multicast
//	::ffff:0:0/96    IPv4-mapped → re-checked against the IPv4 list
package guard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

var (
	// ErrBlockedPrivateIP is returned when any resolved address is
	// private or reserved; the offending IP is included in the text.
	ErrBlockedPrivateIP = errors.New("blocked_private_ip")
	// ErrTargetResolveFailed is returned when the target host cannot be
	// resolved; jobs fail closed in this case.
	ErrTargetResolveFailed = errors.New("target_resolve_failed")
)

// ResolveTimeout bounds the DNS lookup performed by CheckHost so job
// latency is not hurt by slow resolvers.
const ResolveTimeout = 3 * time.Second

// ResolveFunc resolves a host to its addresses; it is a parameter so
// tests (and callers with custom resolvers) can stub it.
type ResolveFunc func(ctx context.Context, host string) ([]net.IP, error)

// Check reports whether ip is private or reserved (true = blocked).
// IPv4-mapped IPv6 addresses are re-checked against the IPv4 list.
func Check(ip net.IP) bool {
	if ip == nil {
		return true // fail closed on unknown addresses
	}
	if v4 := ip.To4(); v4 != nil {
		return checkIPv4(v4)
	}
	return checkIPv6(ip.To16())
}

// CheckHost resolves host (unless it is already a literal IP) and returns
// an error if ANY resolved IP is blocked. Resolution failures also return
// an error: the guard is fail-closed by design.
func CheckHost(ctx context.Context, host string, resolve ResolveFunc) error {
	_, err := ResolveHost(ctx, host, resolve, "")
	return err
}

// ResolveHost resolves and validates host, returning one already-validated
// address suitable for passing to an external network tool. family is
// "ipv4", "ipv6", or empty (any family). Returning the selected address is
// important: resolving again in the tool would re-open a DNS TOCTOU window.
func ResolveHost(ctx context.Context, host string, resolve ResolveFunc, family string) (net.IP, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, fmt.Errorf("%w: empty target", ErrTargetResolveFailed)
	}
	if ip := net.ParseIP(host); ip != nil {
		if Check(ip) {
			return nil, fmt.Errorf("%w: %s", ErrBlockedPrivateIP, ip)
		}
		if !matchesFamily(ip, family) {
			return nil, fmt.Errorf("%w: address family mismatch", ErrTargetResolveFailed)
		}
		return ip, nil
	}
	if resolve == nil {
		resolve = defaultResolve
	}
	rctx, cancel := context.WithTimeout(ctx, ResolveTimeout)
	defer cancel()
	ips, err := resolve(rctx, host)
	if err != nil {
		return nil, fmt.Errorf("%w for %q: %v", ErrTargetResolveFailed, host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w for %q: no records", ErrTargetResolveFailed, host)
	}
	for _, ip := range ips {
		if Check(ip) {
			return nil, fmt.Errorf("%w: %s", ErrBlockedPrivateIP, ip)
		}
	}
	for _, ip := range ips {
		if matchesFamily(ip, family) {
			return ip, nil
		}
	}
	return nil, fmt.Errorf("%w for %q: no %s records", ErrTargetResolveFailed, host, family)
}

func matchesFamily(ip net.IP, family string) bool {
	switch family {
	case "ipv4":
		return ip.To4() != nil
	case "ipv6":
		return ip.To4() == nil && ip.To16() != nil
	default:
		return ip.To16() != nil
	}
}

func defaultResolve(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		ips = append(ips, addr.IP)
	}
	return ips, nil
}

func checkIPv4(b []byte) bool {
	a := b[0]
	switch {
	case a == 0, a == 10, a == 127:
		return true
	case a == 100 && b[1] >= 64 && b[1] <= 127: // CGNAT
		return true
	case a == 169 && b[1] == 254: // link-local
		return true
	case a == 172 && b[1] >= 16 && b[1] <= 31: // private
		return true
	case a == 192 && b[1] == 0 && b[2] == 0: // IETF protocol assignments
		return true
	case a == 192 && b[1] == 168: // private
		return true
	case a == 198 && (b[1] == 18 || b[1] == 19): // benchmarking
		return true
	case a >= 224 && a <= 239: // multicast
		return true
	case a >= 240: // reserved, includes 255.255.255.255
		return true
	default:
		return false
	}
}

func checkIPv6(b []byte) bool {
	allZero := true
	for _, c := range b {
		if c != 0 {
			allZero = false
			break
		}
	}
	if allZero { // ::/128 unspecified
		return true
	}
	if isZeroBytes(b[:10]) {
		if b[10] == 0xff && b[11] == 0xff { // IPv4-mapped ::ffff:a.b.c.d
			return checkIPv4(b[12:16])
		}
		if b[10] == 0 && b[11] == 0 && !isZeroBytes(b[12:16]) { // deprecated IPv4-compatible ::a.b.c.d
			return checkIPv4(b[12:16])
		}
	}
	loopback := isZeroBytes(b[:15]) && b[15] == 1
	uniqueLocal := b[0]&0xfe == 0xfc
	linkLocal := b[0] == 0xfe && b[1]&0xc0 == 0x80
	multicast := b[0] == 0xff
	return loopback || uniqueLocal || linkLocal || multicast
}

func isZeroBytes(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
