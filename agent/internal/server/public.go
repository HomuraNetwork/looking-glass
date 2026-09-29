package server

import (
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"hlg/internal/download"
	"hlg/internal/lgjob"
	"hlg/internal/token"
)

type JobRunner interface {
	Run(context.Context, token.JobClaims, io.Writer) error
}

type JobRunnerFunc func(context.Context, token.JobClaims, io.Writer) error

func (f JobRunnerFunc) Run(ctx context.Context, claims token.JobClaims, w io.Writer) error {
	return f(ctx, claims, w)
}

type PublicOptions struct {
	NodeID             string
	Domain             string
	Features           []string
	HasIPv4            bool
	HasIPv6            bool
	PublicIPv4         string
	PublicIPv6         string
	PublicIPv4Provider func() string
	PublicIPv6Provider func() string
	Verifier           *token.Verifier
	JobRunner          JobRunner
	DownloadReporter   DownloadReporter
	AllowedOrigin      string
	// DownloadConcurrency caps concurrent download streams; 0 falls back
	// to the default (config.Defaults).
	DownloadConcurrency int
	// DownloadBudget limits replays per download token; nil disables the
	// budget check (not recommended).
	DownloadBudget *download.Budget
	// JobConcurrencyPerIP caps concurrent jobs per client IP; 0 falls
	// back to the default.
	JobConcurrencyPerIP int
	// JobConcurrencyGlobal caps total concurrent jobs on this agent.
	// It protects legacy claims without serializing unrelated clients.
	JobConcurrencyGlobal int
	// JobTimeoutSec overrides the per-job wall clock; sane bounds are
	// applied (0 falls back to the default).
	JobTimeoutSec int
	// JobMaxOutputBytes caps total job output written to the client; 0
	// falls back to lgjob.DefaultOutputLimit. Values are sanitized by
	// lgjob.RunLimit (<= 0 keeps the default).
	JobMaxOutputBytes int64
	// GuardPrivateIP enables the execute-time private-IP guard for job
	// targets (defense in depth against DNS rebinding: the agent
	// re-resolves the target and rejects private/reserved addresses).
	// Defaults to true when the runner is the built-in lgjob.Runner.
	GuardPrivateIP *bool
	// JobTools maps a job tool name to its resolved binary path, recorded at
	// install time. Used by the built-in runner; missing entries fall back to PATH.
	JobTools map[string]string
}

type DownloadReport struct {
	LinkID string
	Size   string
}

type DownloadReporter interface {
	ReportDownload(context.Context, DownloadReport) error
}

type DownloadReporterFunc func(context.Context, DownloadReport) error

func (f DownloadReporterFunc) ReportDownload(ctx context.Context, report DownloadReport) error {
	return f(ctx, report)
}

const publicWSWriteTimeout = 5 * time.Second

const (
	defaultDownloadConcurrency  = 2
	defaultJobConcurrencyPerIP  = 1
	defaultJobConcurrencyGlobal = 32
	defaultJobTimeoutSec        = 45
	// Job timeout clamps: keep any misconfigured bundle from disabling
	// the wall clock entirely or starving jobs too early.
	minJobTimeoutSec = 10
	maxJobTimeoutSec = 120
	// MTR streams live output, so keep its cap slightly smaller than the
	// generic one; min(configured, 60s) preserves the old 25s default
	// while still honoring a larger configured timeout when present.
	mtrMaxJobTimeoutSec = 60
)

// builtinRunner builds the default lgjob.Runner from the configured output
// limit. The bundle's job_max_output_bytes flows through PublicOptions; zero
// keeps the lgjob default (RunLimit treats <= 0 as DefaultOutputLimit).
func builtinRunner(opts PublicOptions) lgjob.Runner {
	runner := lgjob.Runner{Tools: opts.JobTools}
	if opts.JobMaxOutputBytes > 0 {
		runner.MaxOutputBytes = opts.JobMaxOutputBytes
	}
	return runner
}

func NewPublicHandler(opts PublicOptions) http.Handler {
	// Default the execute-time guard on for the built-in runner so all
	// job paths are covered; an explicit *bool from the bundle wins.
	// The guard itself lives in lgjob.Runner.Run so every caller of the
	// runner (not just this handler) is protected.
	if opts.GuardPrivateIP == nil {
		enabled := true
		opts.GuardPrivateIP = &enabled
	}
	if opts.JobRunner == nil {
		opts.JobRunner = builtinRunner(opts)
	}
	opts.JobRunner = applyRunnerGuardFlag(opts.JobRunner, opts.GuardPrivateIP)
	downloadSem := newSemaphore(defaultDownloadConcurrency)
	if opts.DownloadConcurrency > 0 {
		downloadSem = newSemaphore(opts.DownloadConcurrency)
	}
	jobLimiter := newIPJobLimiter(defaultJobConcurrencyPerIP)
	if opts.JobConcurrencyPerIP > 0 {
		jobLimiter = newIPJobLimiter(opts.JobConcurrencyPerIP)
	}
	jobGlobalSem := newSemaphore(defaultJobConcurrencyGlobal)
	if opts.JobConcurrencyGlobal > 0 {
		jobGlobalSem = newSemaphore(opts.JobConcurrencyGlobal)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/generate_204", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
			return
		}
		setPublicHeaders(w, opts, r)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
			return
		}
		setPublicHeaders(w, opts, r)
		publicIPv4 := currentPublicIPv4(opts)
		publicIPv6 := currentPublicIPv6(opts)
		writeJSON(w, http.StatusOK, map[string]any{
			"node":     opts.NodeID,
			"domain":   opts.Domain,
			"features": opts.Features,
			"has_ipv4": opts.HasIPv4 || publicIPv4 != "",
			"has_ipv6": opts.HasIPv6 || publicIPv6 != "",
			"ipv4":     publicIPv4,
			"ipv6":     publicIPv6,
		})
	})
	mux.HandleFunc("/download/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
			return
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/download/"), "/")
		if len(parts) != 2 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_download_path"})
			return
		}
		claims, err := opts.Verifier.VerifyDownload(r.Context(), parts[0], token.RequestContext{
			ClientIP: clientIP(r),
			NodeID:   opts.NodeID,
		})
		if err != nil || (claims.Size != "" && claims.Size != "*" && claims.Size != parts[1]) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
			return
		}
		if !opts.Verifier.AllowsDownloadSize(parts[1]) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
			return
		}
		size, err := download.SizeBytes(parts[1])
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_size"})
			return
		}
		// Cheap rejection paths first: a saturated or over-budget token
		// must not trigger random byte generation.
		if !downloadSem.tryAcquire() {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "download_busy"})
			return
		}
		defer downloadSem.release()
		if opts.DownloadBudget != nil && !opts.DownloadBudget.Allow(parts[0], size, time.Now()) {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "download_limit_exceeded"})
			return
		}
		setPublicHeaders(w, opts, r)
		w.Header().Set("content-type", "application/octet-stream")
		w.Header().Set("content-disposition", "attachment; filename=hlg-"+parts[1]+".bin")
		w.Header().Set("content-encoding", "identity")
		w.Header().Set("content-length", strconv.FormatInt(size, 10))
		if err := download.WriteVirtual(w, size); err == nil && opts.DownloadReporter != nil && claims.LinkID != "" {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = opts.DownloadReporter.ReportDownload(ctx, DownloadReport{LinkID: claims.LinkID, Size: parts[1]})
		}
	})
	mux.HandleFunc("/jobs/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
			return
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/jobs/"), "/")
		if len(parts) != 2 || parts[1] != "ws" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_job_path"})
			return
		}
		claims, err := opts.Verifier.VerifyJob(r.Context(), parts[0], token.RequestContext{
			ClientIP: clientIP(r),
			NodeID:   opts.NodeID,
		})
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
			return
		}
		if !websocket.IsWebSocketUpgrade(r) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "websocket_upgrade_required"})
			return
		}
		// Direct visitors are keyed by their TCP peer. Proxied jobs carry the
		// authenticated browser IP in the signed claim, avoiding a shared
		// Cloudflare egress bucket while preserving reconnect accounting.
		limiterKey := clientIP(r)
		if claims.IPBinding == "none" {
			// Worker-issued claims retain the authenticated browser IP even
			// when target IP binding is disabled. Use it for reconnect-safe
			// concurrency accounting; fall back to a synthetic bucket only
			// for legacy claims that predate this field.
			limiterKey = claims.IP
		}
		release, ok := jobLimiter.acquireKeyed(limiterKey)
		if !ok {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "job_concurrency_limit"})
			return
		}
		defer release()
		if !jobGlobalSem.tryAcquire() {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "job_concurrency_limit"})
			return
		}
		defer jobGlobalSem.release()
		upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return originAllowed(r, opts) }}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		ctx, cancel := context.WithTimeout(r.Context(), jobTimeout(claims, opts.JobTimeoutSec))
		defer cancel()
		// Keep a reader alive so a disconnected browser cancels the command
		// immediately instead of holding the per-client slot until its next
		// output or timeout. The runner is the sole writer; this goroutine
		// only observes the peer and closes the context.
		go func() {
			conn.SetReadLimit(1024)
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					cancel()
					return
				}
			}
		}()
		writer := websocketWriter{conn: conn}
		_ = opts.JobRunner.Run(ctx, claims, writer)
	})
	return mux
}

// applyRunnerGuardFlag threads the bundle's guard_private_ip flag into
// a built-in lgjob.Runner. Custom runners are returned unchanged (they
// own their guard behavior).
func applyRunnerGuardFlag(runner JobRunner, guardPrivateIP *bool) JobRunner {
	if r, ok := runner.(lgjob.Runner); ok {
		r.GuardPrivateIP = guardPrivateIP
		return r
	}
	return runner
}

func currentPublicIPv4(opts PublicOptions) string {
	if opts.PublicIPv4Provider != nil {
		return opts.PublicIPv4Provider()
	}
	return opts.PublicIPv4
}

func currentPublicIPv6(opts PublicOptions) string {
	if opts.PublicIPv6Provider != nil {
		return opts.PublicIPv6Provider()
	}
	return opts.PublicIPv6
}

func jobTimeout(claims token.JobClaims, configured int) time.Duration {
	if configured == 0 {
		configured = defaultJobTimeoutSec
	}
	if configured < minJobTimeoutSec {
		configured = minJobTimeoutSec
	}
	if configured > maxJobTimeoutSec {
		configured = maxJobTimeoutSec
	}
	if claims.Tool == "mtr" && configured > mtrMaxJobTimeoutSec {
		configured = mtrMaxJobTimeoutSec
	}
	return time.Duration(configured) * time.Second
}

func setPublicHeaders(w http.ResponseWriter, opts PublicOptions, r *http.Request) {
	w.Header().Set("cache-control", "no-store")
	if opts.AllowedOrigin != "" {
		w.Header().Set("timing-allow-origin", opts.AllowedOrigin)
		if originAllowed(r, opts) {
			w.Header().Set("access-control-allow-origin", r.Header.Get("origin"))
		}
	}
}

func originAllowed(r *http.Request, opts PublicOptions) bool {
	origin := r.Header.Get("origin")
	if origin == "" {
		return true
	}
	return origin == opts.AllowedOrigin || origin == "https://"+opts.Domain
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

type websocketWriter struct {
	conn *websocket.Conn
}

func (w websocketWriter) Write(p []byte) (int, error) {
	_ = w.conn.SetWriteDeadline(time.Now().Add(publicWSWriteTimeout))
	if err := w.conn.WriteMessage(websocket.TextMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}
