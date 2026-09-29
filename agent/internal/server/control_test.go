package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"hlg/internal/iperf"
)

func TestControlHandlerOpensAndClosesIperf(t *testing.T) {
	process := newFakeIperfProcess()
	manager := iperf.NewManager(iperf.Config{
		Host:        "testnode01.lgtest-node.example",
		PortMin:     33000,
		PortMax:     33000,
		TTL:         time.Minute,
		ActiveLimit: 1,
		StartServer: func(context.Context, int, int, int, int, int, func(iperf.Event)) (iperf.Process, error) {
			return process, nil
		},
		ConfirmListen: func(context.Context, int) error { return nil },
	})
	handler := NewControlHandler(ControlOptions{Iperf: manager})

	openReq := httptest.NewRequest(http.MethodPost, "/_lg/control/iperf/open", strings.NewReader(`{
		"session_id":"ipf_test",
		"duration":10,
		"parallel":1,
		"ttl":30
	}`))
	openReq.Header.Set("content-type", "application/json")
	openRes := httptest.NewRecorder()
	handler.ServeHTTP(openRes, openReq)
	if openRes.Code != http.StatusOK {
		t.Fatalf("open status=%d body=%s", openRes.Code, openRes.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(openRes.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["port"].(float64) != 33000 || body["command"] == "" {
		t.Fatalf("open body=%v", body)
	}
	if body["mode"] != "tcp" || body["reverse"] != false {
		t.Fatalf("open flow fields=%v", body)
	}

	closeReq := httptest.NewRequest(http.MethodPost, "/_lg/control/iperf/close", strings.NewReader(`{"session_id":"ipf_test"}`))
	closeReq.Header.Set("content-type", "application/json")
	closeRes := httptest.NewRecorder()
	handler.ServeHTTP(closeRes, closeReq)
	if closeRes.Code != http.StatusOK {
		t.Fatalf("close status=%d body=%s", closeRes.Code, closeRes.Body.String())
	}
}

func TestControlHandlerRejectsOversizedIperfOpenBody(t *testing.T) {
	manager := iperf.NewManager(iperf.Config{
		Host:        "testnode01.lgtest-node.example",
		PortMin:     33000,
		PortMax:     33000,
		TTL:         time.Minute,
		ActiveLimit: 1,
	})
	handler := NewControlHandler(ControlOptions{Iperf: manager})

	body := `{"session_id":"` + strings.Repeat("x", maxControlJSONBodyBytes) + `"}`
	openReq := httptest.NewRequest(http.MethodPost, "/_lg/control/iperf/open", strings.NewReader(body))
	openReq.Header.Set("content-type", "application/json")
	openRes := httptest.NewRecorder()
	handler.ServeHTTP(openRes, openReq)

	if openRes.Code != http.StatusBadRequest {
		t.Fatalf("oversized open status=%d body=%s", openRes.Code, openRes.Body.String())
	}
}

func TestControlHandlerDoesNotLeakIperfOpenErrors(t *testing.T) {
	manager := iperf.NewManager(iperf.Config{
		Host:        "testnode01.lgtest-node.example",
		PortMin:     33000,
		PortMax:     33000,
		TTL:         time.Minute,
		ActiveLimit: 1,
		StartServer: func(context.Context, int, int, int, int, int, func(iperf.Event)) (iperf.Process, error) {
			return nil, errors.New("listen tcp 10.0.0.2:33000: bind: secret host detail")
		},
		ConfirmListen: func(context.Context, int) error { return nil },
	})
	handler := NewControlHandler(ControlOptions{Iperf: manager})
	openReq := httptest.NewRequest(http.MethodPost, "/_lg/control/iperf/open", strings.NewReader(`{"session_id":"ipf_error","ttl":30}`))
	openReq.Header.Set("content-type", "application/json")
	openRes := httptest.NewRecorder()
	handler.ServeHTTP(openRes, openReq)

	if openRes.Code != http.StatusBadRequest {
		t.Fatalf("open status=%d body=%s", openRes.Code, openRes.Body.String())
	}
	if strings.Contains(openRes.Body.String(), "secret host detail") {
		t.Fatalf("response leaked internal error: %s", openRes.Body.String())
	}
	if !strings.Contains(openRes.Body.String(), "iperf_open_failed") {
		t.Fatalf("response missing public error code: %s", openRes.Body.String())
	}
}

func TestControlHandlerRejectsIperfEventWebsocketForeignOrigin(t *testing.T) {
	manager := iperf.NewManager(iperf.Config{
		Host:        "testnode01.lgtest-node.example",
		PortMin:     33000,
		PortMax:     33000,
		TTL:         time.Minute,
		ActiveLimit: 1,
		StartServer: func(context.Context, int, int, int, int, int, func(iperf.Event)) (iperf.Process, error) {
			return newFakeIperfProcess(), nil
		},
		ConfirmListen: func(context.Context, int) error { return nil },
	})
	handler := NewControlHandler(ControlOptions{Iperf: manager, AllowedOrigin: "https://lg.example.net"})
	openReq := httptest.NewRequest(http.MethodPost, "/_lg/control/iperf/open", strings.NewReader(`{"session_id":"ipf_origin","ttl":30}`))
	openReq.Header.Set("content-type", "application/json")
	openRes := httptest.NewRecorder()
	handler.ServeHTTP(openRes, openReq)
	if openRes.Code != http.StatusOK {
		t.Fatalf("open status=%d body=%s", openRes.Code, openRes.Body.String())
	}

	eventsReq := httptest.NewRequest(http.MethodGet, "/_lg/control/iperf/events?session_id=ipf_origin", nil)
	eventsReq.Header.Set("upgrade", "websocket")
	eventsReq.Header.Set("connection", "upgrade")
	eventsReq.Header.Set("sec-websocket-version", "13")
	eventsReq.Header.Set("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
	eventsReq.Header.Set("origin", "https://evil.example.net")
	eventsRes := httptest.NewRecorder()
	handler.ServeHTTP(eventsRes, eventsReq)
	if eventsRes.Code != http.StatusForbidden {
		t.Fatalf("events status=%d body=%s", eventsRes.Code, eventsRes.Body.String())
	}
}

type fakeIperfProcess struct {
	done chan struct{}
}

func newFakeIperfProcess() *fakeIperfProcess {
	return &fakeIperfProcess{done: make(chan struct{})}
}

func TestControlHandlerCertReloadTriggersSync(t *testing.T) {
	called := 0
	handler := NewControlHandler(ControlOptions{
		Reload: func(context.Context) error {
			called++
			return nil
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/_lg/control/cert/reload", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("reload status=%d body=%s", res.Code, res.Body.String())
	}
	if called != 1 {
		t.Fatalf("reload callback called %d times, want 1", called)
	}
}

func TestControlHandlerCertReloadReportsFailure(t *testing.T) {
	handler := NewControlHandler(ControlOptions{
		Reload: func(context.Context) error {
			return errors.New("pull failed")
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/_lg/control/cert/reload", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusBadGateway {
		t.Fatalf("reload failure status=%d, want 502", res.Code)
	}
	if !strings.Contains(res.Body.String(), "pull failed") {
		t.Fatalf("reload failure body=%s", res.Body.String())
	}
}

func (p *fakeIperfProcess) Kill() error {
	select {
	case <-p.done:
	default:
		close(p.done)
	}
	return nil
}

func (p *fakeIperfProcess) Wait() error {
	<-p.done
	return nil
}
