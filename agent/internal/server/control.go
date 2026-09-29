package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"hlg/internal/config"
	"hlg/internal/iperf"

	"github.com/gorilla/websocket"
)

type ControlOptions struct {
	Iperf         *iperf.Manager
	Admin         *AdminVerifier
	Bundle        *config.SignedBundle
	AllowedOrigin string
	// Reload, when set, is invoked by POST /_lg/control/cert/reload and
	// /_lg/control/sync to trigger an immediate controller sync (config +
	// certificate pull) instead of waiting for the periodic interval. It should
	// return promptly; the handler reports the outcome to the controller.
	Reload func(ctx context.Context) error
}

const (
	maxControlJSONBodyBytes = 64 << 10 // 64 KiB
	controlWSWriteTimeout   = 5 * time.Second
)

func NewControlHandler(opts ControlOptions) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/_lg/control/iperf/open", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
			return
		}
		var req iperf.OpenRequest
		if err := decodeControlJSON(w, r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_json"})
			return
		}
		session, err := opts.Iperf.Open(r.Context(), req)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": publicIperfError(err, "iperf_open_failed")})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":         true,
			"session_id": session.SessionID,
			"host":       session.Host,
			"port":       session.Port,
			"expires_at": session.ExpiresAt.Unix(),
			"max_runs":   session.MaxRuns,
			"run_budget": session.RunBudget,
			"reused":     session.Reused,
			"command":    session.Command,
			"mode":       session.Mode,
			"reverse":    session.Reverse,
		})
	})
	mux.HandleFunc("/_lg/control/iperf/close", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
			return
		}
		var req struct {
			SessionID string `json:"session_id"`
		}
		if err := decodeControlJSON(w, r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_json"})
			return
		}
		if err := opts.Iperf.Close(req.SessionID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": publicIperfError(err, "iperf_close_failed")})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "closed_at": time.Now().Unix()})
	})
	mux.HandleFunc("/_lg/control/iperf/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
			return
		}
		if !websocket.IsWebSocketUpgrade(r) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "websocket_upgrade_required"})
			return
		}
		sessionID := r.URL.Query().Get("session_id")
		if sessionID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_session_id"})
			return
		}
		events, cancel, err := opts.Iperf.Subscribe(sessionID)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": publicIperfError(err, "iperf_events_failed")})
			return
		}
		defer cancel()
		upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return controlOriginAllowed(r, opts) }}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetReadLimit(1024)
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
			}
		}()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case event, ok := <-events:
				if !ok {
					return
				}
				_ = conn.SetWriteDeadline(time.Now().Add(controlWSWriteTimeout))
				if err := conn.WriteJSON(event); err != nil {
					return
				}
			case <-ticker.C:
				event, err := opts.Iperf.Status(sessionID)
				if err != nil {
					return
				}
				_ = conn.SetWriteDeadline(time.Now().Add(controlWSWriteTimeout))
				if err := conn.WriteJSON(event); err != nil {
					return
				}
			case <-done:
				return
			}
		}
	})
	mux.HandleFunc("/_lg/control/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
			return
		}
		if opts.Bundle == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "config_not_loaded"})
			return
		}
		writeJSON(w, http.StatusOK, opts.Bundle)
	})
	mux.HandleFunc("/_lg/control/keyset", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
			return
		}
		if opts.Bundle == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "config_not_loaded"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"keyset": opts.Bundle.Keyset})
	})
	mux.HandleFunc("/_lg/control/sync", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
			return
		}
		runReload(w, r, opts)
	})
	mux.HandleFunc("/_lg/control/cert/reload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
			return
		}
		runReload(w, r, opts)
	})
	if opts.Admin != nil {
		return opts.Admin.Middleware(mux)
	}
	return mux
}

func decodeControlJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxControlJSONBodyBytes)
	return json.NewDecoder(r.Body).Decode(dst)
}

func publicIperfError(err error, fallback string) string {
	switch {
	case errors.Is(err, iperf.ErrLimit):
		return "iperf_limit"
	case errors.Is(err, iperf.ErrNotFound):
		return "iperf_session_not_found"
	case errors.Is(err, iperf.ErrBadRequest):
		return "bad_iperf_request"
	default:
		return fallback
	}
}

func controlOriginAllowed(r *http.Request, opts ControlOptions) bool {
	origin := r.Header.Get("origin")
	if origin == "" {
		return true
	}
	return opts.AllowedOrigin != "" && origin == opts.AllowedOrigin
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// runReload triggers a synchronous controller sync when configured, and reports
// the outcome. The controller uses the response to count failures/retries.
func runReload(w http.ResponseWriter, r *http.Request, opts ControlOptions) {
	if opts.Reload == nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "reloaded_at": time.Now().Unix(), "skipped": "reload_not_configured"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := opts.Reload(ctx); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "reloaded_at": time.Now().Unix()})
}
