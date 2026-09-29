package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"hlg/internal/config"
	"hlg/internal/guard"
	"hlg/internal/keyset"
	"hlg/internal/lgjob"
	"hlg/internal/signing"
	"hlg/internal/token"
)

func TestPublicHandlerRequiredEndpoints(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := keyset.New([]config.Key{{
		KID:       "kid-a",
		Alg:       "Ed25519",
		Use:       "token_verify",
		PublicKey: base64.RawURLEncoding.EncodeToString(pub),
	}})
	if err != nil {
		t.Fatal(err)
	}
	verifier := token.NewVerifier(token.VerifierConfig{
		NodeID:               "testnode01",
		Keyset:               ks,
		AllowedDownloadSizes: []string{"10M"},
		AllowedTools:         []string{"ping"},
		NonceCache:           token.NewNonceCache(100, time.Minute),
	})
	var downloadReports []DownloadReport
	ipv4 := "198.51.100.10"
	ipv6 := "2001:db8::10"
	handler := NewPublicHandler(PublicOptions{
		NodeID:             "testnode01",
		Domain:             "testnode01.lgtest-node.example",
		Features:           []string{"generate204", "download", "ping"},
		HasIPv4:            true,
		HasIPv6:            true,
		PublicIPv4Provider: func() string { return ipv4 },
		PublicIPv6Provider: func() string { return ipv6 },
		Verifier:           verifier,
		JobRunner: JobRunnerFunc(func(context.Context, token.JobClaims, io.Writer) error {
			_, _ = io.WriteString(io.Discard, "unused")
			return nil
		}),
		DownloadReporter: DownloadReporterFunc(func(_ context.Context, report DownloadReport) error {
			downloadReports = append(downloadReports, report)
			return nil
		}),
	})

	probe := httptest.NewRecorder()
	handler.ServeHTTP(probe, httptest.NewRequest(http.MethodGet, "/generate_204", nil))
	if probe.Code != http.StatusNoContent || probe.Header().Get("cache-control") != "no-store" {
		t.Fatalf("probe status=%d headers=%v", probe.Code, probe.Header())
	}

	ipv4 = "198.51.100.44"
	ipv6 = "2001:db8::44"
	info := httptest.NewRecorder()
	handler.ServeHTTP(info, httptest.NewRequest(http.MethodGet, "/info", nil))
	if info.Code != http.StatusOK || !containsBody(info.Body.String(), ipv4) || !containsBody(info.Body.String(), ipv6) {
		t.Fatalf("info status=%d body=%s", info.Code, info.Body.String())
	}

	downloadToken, err := signing.SignCompact(token.DownloadClaims{
		BaseClaims: token.BaseClaims{
			Type:      "download",
			KID:       "kid-a",
			Node:      "testnode01",
			IPBinding: "none",
			ExpiresAt: time.Now().Add(time.Minute).Unix(),
			Nonce:     "download-nonce-abcdefghijklmnop",
		},
		Size:   "10M",
		LinkID: "dl_test_report",
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	download := httptest.NewRecorder()
	downloadRequest := httptest.NewRequest(http.MethodGet, "/download/"+downloadToken+"/10M", nil)
	downloadRequest.Header.Set("accept-encoding", "gzip")
	handler.ServeHTTP(download, downloadRequest)
	if download.Code != http.StatusOK || download.Body.Len() == 0 {
		t.Fatalf("download status=%d len=%d", download.Code, download.Body.Len())
	}
	if download.Header().Get("cache-control") != "no-store" || download.Header().Get("content-encoding") != "identity" {
		t.Fatalf("download cache/encoding headers = %v", download.Header())
	}
	if got := download.Header().Get("content-disposition"); got != "attachment; filename=hlg-10M.bin" {
		t.Fatalf("download filename = %q", got)
	}
	if len(downloadReports) != 1 || downloadReports[0].LinkID != "dl_test_report" || downloadReports[0].Size != "10M" {
		t.Fatalf("download reports = %#v", downloadReports)
	}

	jobToken, err := signing.SignCompact(token.JobClaims{
		BaseClaims: token.BaseClaims{
			Type:      "job",
			KID:       "kid-a",
			Node:      "testnode01",
			IPBinding: "none",
			ExpiresAt: time.Now().Add(time.Minute).Unix(),
			Nonce:     "job-nonce-abcdefghijklmnop",
		},
		Tool:   "ping",
		Target: "1.1.1.1",
		IPVer:  "ipv4",
		Count:  4,
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	ws := httptest.NewRecorder()
	handler.ServeHTTP(ws, httptest.NewRequest(http.MethodGet, "/jobs/"+jobToken+"/ws", nil))
	if ws.Code != http.StatusBadRequest {
		t.Fatalf("ws status=%d body=%s", ws.Code, ws.Body.String())
	}
}

func TestPublicJobsUseSignedBrowserIPAndCancelOnDisconnect(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := keyset.New([]config.Key{{KID: "kid", Alg: "Ed25519", Use: "token_verify", PublicKey: base64.RawURLEncoding.EncodeToString(pub)}})
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{}, 4)
	ctxDone := make(chan struct{}, 4)
	h := NewPublicHandler(PublicOptions{
		NodeID: "node", Verifier: token.NewVerifier(token.VerifierConfig{NodeID: "node", Keyset: ks, AllowedTools: []string{"ping"}, NonceCache: token.NewNonceCache(100, time.Minute)}),
		JobRunner: JobRunnerFunc(func(ctx context.Context, claims token.JobClaims, _ io.Writer) error {
			started <- struct{}{}
			<-ctx.Done()
			if claims.IP == "203.0.113.7" {
				ctxDone <- struct{}{}
			}
			return ctx.Err()
		}),
	})
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("network listener unavailable: %v", err)
	}
	ts := &httptest.Server{Listener: listener, Config: &http.Server{Handler: h}}
	ts.Start()
	defer ts.Close()
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/jobs/"
	makeToken := func(ip, nonce string) string {
		raw, e := signing.SignCompact(token.JobClaims{BaseClaims: token.BaseClaims{Type: "job", KID: "kid", Node: "node", IP: ip, IPBinding: "none", ExpiresAt: time.Now().Add(time.Minute).Unix(), Nonce: nonce}, Tool: "ping", Target: "1.1.1.1", IPVer: "ipv4"}, priv)
		if e != nil {
			t.Fatal(e)
		}
		return raw
	}
	first, _, err := websocket.DefaultDialer.Dial(wsURL+makeToken("203.0.113.7", "nonce-first-000001")+"/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first job did not start")
	}
	_, resp, err := websocket.DefaultDialer.Dial(wsURL+makeToken("203.0.113.7", "nonce-second-00002")+"/ws", nil)
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	if err == nil || resp == nil || resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("same-IP second connection: err=%v status=%v", err, resp)
	}
	other, _, err := websocket.DefaultDialer.Dial(wsURL+makeToken("203.0.113.8", "nonce-other-000003")+"/ws", nil)
	if err != nil {
		t.Fatalf("different signed IP should run concurrently: %v", err)
	}
	other.Close()
	first.Close()
	select {
	case <-ctxDone:
	case <-time.After(time.Second):
		t.Fatal("job context was not canceled after disconnect")
	}
	// The released slot permits a reconnect by the same signed browser IP.
	var reconnected *websocket.Conn
	deadline := time.Now().Add(time.Second)
	for reconnected == nil && time.Now().Before(deadline) {
		var resp *http.Response
		reconnected, resp, err = websocket.DefaultDialer.Dial(wsURL+makeToken("203.0.113.7", fmt.Sprintf("reconnect-%d", time.Now().UnixNano()))+"/ws", nil)
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		if reconnected == nil {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if err != nil && reconnected == nil {
		t.Fatalf("slot not released after disconnect: %v", err)
	}
	reconnected.Close()
}

func TestPublicJobsGlobalConcurrencyCap(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := keyset.New([]config.Key{{KID: "kid", Alg: "Ed25519", Use: "token_verify", PublicKey: base64.RawURLEncoding.EncodeToString(pub)}})
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{}, 2)
	h := NewPublicHandler(PublicOptions{NodeID: "node", JobConcurrencyGlobal: 1, Verifier: token.NewVerifier(token.VerifierConfig{NodeID: "node", Keyset: ks, AllowedTools: []string{"ping"}, NonceCache: token.NewNonceCache(100, time.Minute)}), JobRunner: JobRunnerFunc(func(ctx context.Context, _ token.JobClaims, _ io.Writer) error {
		started <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	})})
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("network listener unavailable: %v", err)
	}
	ts := &httptest.Server{Listener: listener, Config: &http.Server{Handler: h}}
	ts.Start()
	defer ts.Close()
	makeToken := func(ip, nonce string) string {
		raw, e := signing.SignCompact(token.JobClaims{BaseClaims: token.BaseClaims{Type: "job", KID: "kid", Node: "node", IP: ip, IPBinding: "none", ExpiresAt: time.Now().Add(time.Minute).Unix(), Nonce: nonce}, Tool: "ping", Target: "1.1.1.1", IPVer: "ipv4"}, priv)
		if e != nil {
			t.Fatal(e)
		}
		return raw
	}
	u := "ws" + strings.TrimPrefix(ts.URL, "http") + "/jobs/"
	first, _, err := websocket.DefaultDialer.Dial(u+makeToken("203.0.113.1", "global-first-0001")+"/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("global-cap job did not start")
	}
	_, resp, err := websocket.DefaultDialer.Dial(u+makeToken("203.0.113.2", "global-second-02")+"/ws", nil)
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	if err == nil || resp == nil || resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("global cap: err=%v status=%v", err, resp)
	}
}

func TestPublicHandlerUsesRemoteAddrForIPBindingNotSpoofedHeaders(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := keyset.New([]config.Key{{
		KID:       "kid-a",
		Alg:       "Ed25519",
		Use:       "token_verify",
		PublicKey: base64.RawURLEncoding.EncodeToString(pub),
	}})
	if err != nil {
		t.Fatal(err)
	}
	handler := NewPublicHandler(PublicOptions{
		NodeID: "testnode01",
		Verifier: token.NewVerifier(token.VerifierConfig{
			NodeID:               "testnode01",
			Keyset:               ks,
			AllowedDownloadSizes: []string{"10M"},
			NonceCache:           token.NewNonceCache(100, time.Minute),
		}),
	})
	downloadToken, err := signing.SignCompact(token.DownloadClaims{
		BaseClaims: token.BaseClaims{
			Type:      "download",
			KID:       "kid-a",
			Node:      "testnode01",
			IP:        "203.0.113.10",
			IPBinding: "strict",
			ExpiresAt: time.Now().Add(time.Minute).Unix(),
			Nonce:     "download-nonce-remote-addr",
		},
		Size: "10M",
	}, priv)
	if err != nil {
		t.Fatal(err)
	}

	spoofed := httptest.NewRecorder()
	spoofedRequest := httptest.NewRequest(http.MethodGet, "/download/"+downloadToken+"/10M", nil)
	spoofedRequest.RemoteAddr = "198.51.100.44:54321"
	spoofedRequest.Header.Set("x-forwarded-for", "203.0.113.10")
	spoofedRequest.Header.Set("x-real-ip", "203.0.113.10")
	handler.ServeHTTP(spoofed, spoofedRequest)
	if spoofed.Code != http.StatusUnauthorized {
		t.Fatalf("spoofed forwarded headers status=%d", spoofed.Code)
	}

	matchingRemote := httptest.NewRecorder()
	matchingRequest := httptest.NewRequest(http.MethodGet, "/download/"+downloadToken+"/10M", nil)
	matchingRequest.RemoteAddr = "203.0.113.10:54321"
	handler.ServeHTTP(matchingRemote, matchingRequest)
	if matchingRemote.Code != http.StatusOK {
		t.Fatalf("matching remote addr status=%d body=%s", matchingRemote.Code, matchingRemote.Body.String())
	}
}

func TestJobTimeoutDefaults(t *testing.T) {
	if got := jobTimeout(token.JobClaims{Tool: "mtr"}, 0); got != 45*time.Second {
		t.Fatalf("mtr timeout with default config = %s, want 45s", got)
	}
	if got := jobTimeout(token.JobClaims{Tool: "ping"}, 0); got != 45*time.Second {
		t.Fatalf("ping timeout with default config = %s", got)
	}
}

func TestJobTimeoutUsesConfiguredValueWithSaneBounds(t *testing.T) {
	if got := jobTimeout(token.JobClaims{Tool: "ping"}, 60); got != 60*time.Second {
		t.Fatalf("configured timeout = %s, want 60s", got)
	}
	if got := jobTimeout(token.JobClaims{Tool: "ping"}, 5); got != 10*time.Second {
		t.Fatalf("timeout below minimum should clamp to 10s, got %s", got)
	}
	if got := jobTimeout(token.JobClaims{Tool: "ping"}, 500); got != 120*time.Second {
		t.Fatalf("timeout above maximum should clamp to 120s, got %s", got)
	}
	if got := jobTimeout(token.JobClaims{Tool: "mtr"}, 500); got != 60*time.Second {
		t.Fatalf("mtr should cap at 60s even with a large configured value, got %s", got)
	}
	if got := jobTimeout(token.JobClaims{Tool: "mtr"}, 30); got != 30*time.Second {
		t.Fatalf("mtr configured timeout below cap should be honored, got %s", got)
	}
}

func TestDownloadSemaphoreRejectsWhenSaturated(t *testing.T) {
	cases := []struct {
		name      string
		limit     int
		probes    int
		wantFirst bool
		wantExtra bool
	}{
		{name: "limit two allows two", limit: 2, probes: 3, wantFirst: true, wantExtra: false},
		{name: "limit one allows one", limit: 1, probes: 2, wantFirst: true, wantExtra: false},
		{name: "all free", limit: 3, probes: 3, wantFirst: true, wantExtra: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sem := newSemaphore(tc.limit)
			results := make([]bool, tc.probes)
			for i := range results {
				results[i] = sem.tryAcquire()
			}
			if results[0] != tc.wantFirst {
				t.Fatalf("first acquire = %v, want %v", results[0], tc.wantFirst)
			}
			for i := 1; i < tc.probes; i++ {
				got := results[i]
				want := tc.wantExtra
				if i >= tc.limit {
					want = false
				} else {
					want = tc.wantFirst
				}
				if got != want {
					t.Fatalf("acquire[%d] = %v, want %v", i, got, want)
				}
				if got {
					sem.release()
				}
			}
		})
	}
}

func TestDownloadSemaphoreReleaseRestoresSlot(t *testing.T) {
	sem := newSemaphore(1)
	if !sem.tryAcquire() {
		t.Fatal("expected acquire on empty semaphore")
	}
	if sem.tryAcquire() {
		t.Fatal("expected saturated semaphore to reject")
	}
	sem.release()
	if !sem.tryAcquire() {
		t.Fatal("expected acquire after release")
	}
}

func TestIPJobLimiterReleasesSlots(t *testing.T) {
	limiter := newIPJobLimiter(1)
	release, ok := limiter.acquire("203.0.113.7")
	if !ok {
		t.Fatal("expected first job to acquire")
	}
	_, ok = limiter.acquire("203.0.113.7")
	if ok {
		t.Fatal("expected second job on same IP to be rejected")
	}
	otherRelease, ok := limiter.acquire("198.51.100.9")
	if !ok {
		t.Fatal("expected different IP to be unaffected")
	}
	otherRelease()
	release()
	_, ok = limiter.acquire("203.0.113.7")
	if !ok {
		t.Fatal("expected acquire after release")
	}
}

func TestIPJobLimiterDoesNotSerializeUnboundProxiedJobs(t *testing.T) {
	// Proxied jobs (ip_binding "none") all arrive from the worker's egress
	// IP. They must not share the peer-address bucket, or the default
	// limit of 1 would run one proxied job per node at a time.
	limiter := newIPJobLimiter(1)
	releases := make([]func(), 0, 3)
	for i := 0; i < 3; i++ {
		release, ok := limiter.acquireKeyed("")
		if !ok {
			t.Fatalf("expected unbound proxied job %d to acquire", i)
		}
		releases = append(releases, release)
	}
	// Bound jobs on the shared peer address still hit the per-IP limit.
	bound, ok := limiter.acquire("198.51.100.9")
	if !ok {
		t.Fatal("expected first bound job to acquire")
	}
	if _, ok := limiter.acquire("198.51.100.9"); ok {
		t.Fatal("expected second bound job on same IP to be rejected")
	}
	bound()
	for _, release := range releases {
		release()
	}
}

func TestNewPublicHandlerInjectsGuardFlagIntoRunner(t *testing.T) {
	// Explicit bundle opt-out must reach the built-in runner.
	disabled := false
	applied := applyRunnerGuardFlag(lgjob.Runner{}, &disabled)
	if runner, ok := applied.(lgjob.Runner); !ok || runner.GuardPrivateIP == nil || *runner.GuardPrivateIP {
		t.Fatalf("opt-out flag not applied to runner: %#v", applied)
	}
	// nil flag defaults to enabled.
	applied = applyRunnerGuardFlag(lgjob.Runner{}, nil)
	if runner, ok := applied.(lgjob.Runner); !ok || runner.GuardPrivateIP != nil {
		t.Fatalf("nil flag should stay nil (runner defaults to guard on): %#v", applied)
	}
	// Custom runners are passed through unchanged (same behavior, not
	// wrapped): a JobRunnerFunc still runs its own function.
	custom := JobRunnerFunc(func(context.Context, token.JobClaims, io.Writer) error { return nil })
	passed := applyRunnerGuardFlag(custom, &disabled)
	if _, ok := passed.(JobRunnerFunc); !ok {
		t.Fatalf("custom runner should be returned unchanged, got %T", passed)
	}
}

func TestBuiltinRunnerThreadsConfiguredOutputLimit(t *testing.T) {
	// The bundle's job_max_output_bytes must reach the built-in runner;
	// before the wiring it was parsed, merged... and ignored, with the
	// runner always using DefaultOutputLimit.
	if runner := builtinRunner(PublicOptions{JobMaxOutputBytes: 4096}); runner.MaxOutputBytes != 4096 {
		t.Fatalf("expected configured output limit 4096, got %d", runner.MaxOutputBytes)
	}
	// Zero falls back to the lgjob default (RunLimit treats <= 0 as
	// DefaultOutputLimit).
	if runner := builtinRunner(PublicOptions{}); runner.MaxOutputBytes != 0 {
		t.Fatalf("expected zero (default) output limit, got %d", runner.MaxOutputBytes)
	}
}

func TestRunnerGuardBlocksPrivateTargetBeforeExec(t *testing.T) {
	enabled := true
	runner := lgjob.Runner{GuardPrivateIP: &enabled}
	var out bytes.Buffer
	err := runner.Run(context.Background(), token.JobClaims{
		Tool:   "ping",
		Target: "10.0.0.8",
		IPVer:  "ipv4",
	}, &out)
	if !errors.Is(err, guard.ErrBlockedPrivateIP) {
		t.Fatalf("err = %v, want ErrBlockedPrivateIP", err)
	}
	if !strings.Contains(out.String(), "job rejected") {
		t.Fatalf("guard message missing from output: %q", out.String())
	}
}

func TestRunnerGuardFailsClosedOnResolveFailure(t *testing.T) {
	enabled := true
	runner := lgjob.Runner{GuardPrivateIP: &enabled}
	var out bytes.Buffer
	err := runner.Run(context.Background(), token.JobClaims{
		Tool:   "ping",
		Target: "unreachable.invalid",
		IPVer:  "ipv4",
	}, &out)
	if err == nil || !strings.Contains(err.Error(), "target resolve failed") {
		t.Fatalf("err = %v, want target resolve failed", err)
	}
}

func TestRunnerGuardAllowsPublicTarget(t *testing.T) {
	enabled := true
	runner := lgjob.Runner{GuardPrivateIP: &enabled}
	var out bytes.Buffer
	// "nosuchtool" fails inside command() AFTER the guard has passed the
	// public target, proving the guard did not block it — no network use.
	err := runner.Run(context.Background(), token.JobClaims{
		Tool:   "nosuchtool",
		Target: "1.1.1.1",
		IPVer:  "ipv4",
	}, &out)
	if err == nil || !strings.Contains(err.Error(), "unsupported tool") {
		t.Fatalf("err = %v, want unsupported tool (guard should pass a public target)", err)
	}
}

func TestRunnerGuardDisabledWhenBundleOptsOut(t *testing.T) {
	disabled := false
	runner := lgjob.Runner{GuardPrivateIP: &disabled}
	var out bytes.Buffer
	// With the guard off, a private literal target reaches command()
	// (which fails on the unknown tool) instead of being rejected.
	err := runner.Run(context.Background(), token.JobClaims{
		Tool:   "nosuchtool",
		Target: "10.0.0.8",
		IPVer:  "ipv4",
	}, &out)
	if err == nil || !strings.Contains(err.Error(), "unsupported tool") {
		t.Fatalf("err = %v, want unsupported tool (guard must be disabled)", err)
	}
}

func containsBody(body, value string) bool {
	return len(body) >= len(value) && (body == value || len(value) == 0 || stringContains(body, value))
}

func stringContains(body, value string) bool {
	for i := 0; i+len(value) <= len(body); i++ {
		if body[i:i+len(value)] == value {
			return true
		}
	}
	return false
}
