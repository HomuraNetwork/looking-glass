package iperf

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"hlg/internal/logging"
)

var (
	ErrLimit      = errors.New("active iperf session limit reached")
	ErrNotFound   = errors.New("iperf session not found")
	ErrBadRequest = errors.New("bad iperf request")
)

type Process interface {
	Kill() error
	Wait() error
}

type Stats struct {
	Attempts    int
	Spend       int
	CloseReason string
	Mode        string
	Reverse     bool
	ClientSeen  bool
}

type Event struct {
	Type             string `json:"type"`
	SessionID        string `json:"session_id,omitempty"`
	Port             int    `json:"port,omitempty"`
	Line             string `json:"line,omitempty"`
	Command          string `json:"command,omitempty"`
	Mode             string `json:"mode,omitempty"`
	Reverse          bool   `json:"reverse,omitempty"`
	RemainingSeconds int    `json:"remaining_seconds"`
	RemainingRuns    int    `json:"remaining_runs"`
	RunsUsed         int    `json:"runs_used"`
	MaxRuns          int    `json:"max_runs"`
	CloseReason      string `json:"close_reason,omitempty"`
	At               int64  `json:"at"`
}

type Config struct {
	Host        string
	PortMin     int
	PortMax     int
	TTL         time.Duration
	ActiveLimit int
	MaxDuration int
	MaxParallel int
	MaxRuns     int
	RunBudget   int
	DebugOutput bool
	// IperfPath is the resolved iperf3 binary; empty falls back to PATH.
	IperfPath     string
	StartServer   func(context.Context, int, int, int, int, int, func(Event)) (Process, error)
	ConfirmListen func(context.Context, int) error
}

type OpenRequest struct {
	SessionID string `json:"session_id"`
	ClientIP  string `json:"client_ip"`
	Mode      string `json:"mode"`
	Direction string `json:"direction"`
	Reverse   bool   `json:"reverse"`
	Duration  int    `json:"duration"`
	Parallel  int    `json:"parallel"`
	TTL       int    `json:"ttl"`
	MaxRuns   int    `json:"max_runs"`
	RunBudget int    `json:"run_budget"`
}

type Session struct {
	SessionID string    `json:"session_id"`
	Host      string    `json:"host"`
	Port      int       `json:"port"`
	ExpiresAt time.Time `json:"expires_at"`
	MaxRuns   int       `json:"max_runs"`
	RunBudget int       `json:"run_budget"`
	Reused    bool      `json:"reused"`
	Command   string    `json:"command"`
	Mode      string    `json:"mode"`
	Reverse   bool      `json:"reverse"`
	process   Process
	timer     *time.Timer
	events    *eventHub
}

type Manager struct {
	mu           sync.Mutex
	cfg          Config
	sessions     map[string]*Session
	reservations map[string]int
}

type eventHub struct {
	mu          sync.Mutex
	subscribers map[chan Event]struct{}
	closed      bool
}

func newEventHub() *eventHub {
	return &eventHub{subscribers: make(map[chan Event]struct{})}
}

func (h *eventHub) subscribe() (<-chan Event, func(), bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil, func() {}, false
	}
	ch := make(chan Event, 128)
	h.subscribers[ch] = struct{}{}
	cancel := func() {
		h.mu.Lock()
		if _, ok := h.subscribers[ch]; ok {
			delete(h.subscribers, ch)
			close(ch)
		}
		h.mu.Unlock()
	}
	return ch, cancel, true
}

func (h *eventHub) publish(event Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	for ch := range h.subscribers {
		select {
		case ch <- event:
		default:
		}
	}
}

func (h *eventHub) close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	for ch := range h.subscribers {
		close(ch)
		delete(h.subscribers, ch)
	}
}

func NewManager(cfg Config) *Manager {
	if cfg.PortMin == 0 {
		cfg.PortMin = 30000
	}
	if cfg.PortMax == 0 {
		cfg.PortMax = 39999
	}
	if cfg.TTL == 0 {
		cfg.TTL = 120 * time.Second
	}
	if cfg.ActiveLimit == 0 {
		cfg.ActiveLimit = 10
	}
	if cfg.MaxDuration == 0 {
		cfg.MaxDuration = 30
	}
	if cfg.MaxParallel == 0 {
		cfg.MaxParallel = 4
	}
	if cfg.MaxRuns == 0 {
		cfg.MaxRuns = 4
	}
	if cfg.RunBudget == 0 {
		cfg.RunBudget = 200
	}
	if cfg.StartServer == nil {
		iperfPath := cfg.IperfPath
		cfg.StartServer = func(ctx context.Context, port, maxRuns, runBudget, maxParallel, maxDuration int, emit func(Event)) (Process, error) {
			return startIperfServer(ctx, iperfPath, port, maxRuns, runBudget, maxParallel, maxDuration, emit)
		}
	}
	if cfg.ConfirmListen == nil {
		cfg.ConfirmListen = confirmListen
	}
	return &Manager{cfg: cfg, sessions: make(map[string]*Session), reservations: make(map[string]int)}
}

func (m *Manager) Open(ctx context.Context, req OpenRequest) (Session, error) {
	if req.SessionID == "" {
		return Session{}, ErrBadRequest
	}
	mode, reverse, err := normalizeMode(req.Mode, req.Direction, req.Reverse)
	if err != nil {
		return Session{}, err
	}
	duration := clamp(req.Duration, 1, m.cfg.MaxDuration)
	parallel := clamp(req.Parallel, 1, m.cfg.MaxParallel)
	maxRuns := m.cfg.MaxRuns
	if req.MaxRuns > 0 && req.MaxRuns < maxRuns {
		maxRuns = req.MaxRuns
	}
	runBudget := m.cfg.RunBudget
	if req.RunBudget > 0 && req.RunBudget < runBudget {
		runBudget = req.RunBudget
	}
	ttl := m.cfg.TTL
	if req.TTL > 0 && time.Duration(req.TTL)*time.Second < ttl {
		ttl = time.Duration(req.TTL) * time.Second
	}

	m.mu.Lock()
	if session, ok := m.sessions[req.SessionID]; ok {
		// A reused session whose TTL already elapsed must not be handed back:
		// its process/timer are being torn down and its expires_at is in the
		// past, which would mislead the control plane. Release it and treat
		// this open as a new session.
		if time.Now().Before(session.ExpiresAt) {
			reused := *session
			reused.Reused = true
			m.mu.Unlock()
			return reused, nil
		}
		m.mu.Unlock()
		// release() takes the lock itself; call it outside ours.
		_ = m.release(req.SessionID, true, "ttl_expired")
		m.mu.Lock()
	}
	if _, ok := m.reservations[req.SessionID]; ok {
		m.mu.Unlock()
		logging.Infof("iperf open rejected session=%s reason=session_starting", req.SessionID)
		return Session{}, ErrLimit
	}
	if len(m.sessions)+len(m.reservations) >= m.cfg.ActiveLimit {
		active := len(m.sessions)
		reserved := len(m.reservations)
		ports := m.activePortsLocked()
		m.mu.Unlock()
		logging.Infof("iperf open rejected session=%s reason=active_limit active=%d reserved=%d ports=%v limit=%d",
			req.SessionID, active, reserved, ports, m.cfg.ActiveLimit)
		return Session{}, ErrLimit
	}
	port, err := m.pickPortLocked()
	if err != nil {
		m.mu.Unlock()
		return Session{}, err
	}
	m.reservations[req.SessionID] = port
	m.mu.Unlock()

	events := newEventHub()
	expiresAt := time.Now().Add(ttl)
	emit := func(event Event) {
		if event.Type == "debug" && !m.cfg.DebugOutput {
			return
		}
		event.SessionID = req.SessionID
		if event.Port == 0 {
			event.Port = port
		}
		if event.At == 0 {
			event.At = time.Now().Unix()
		}
		events.publish(event)
	}
	process, err := m.cfg.StartServer(context.WithoutCancel(ctx), port, maxRuns, runBudget, m.cfg.MaxParallel, m.cfg.MaxDuration, emit)
	if err != nil {
		m.releaseReservation(req.SessionID)
		events.close()
		return Session{}, err
	}
	if err := m.cfg.ConfirmListen(ctx, port); err != nil {
		_ = process.Kill()
		_ = process.Wait()
		m.releaseReservation(req.SessionID)
		events.close()
		return Session{}, err
	}

	session := &Session{
		SessionID: req.SessionID,
		Host:      m.cfg.Host,
		Port:      port,
		ExpiresAt: expiresAt,
		MaxRuns:   maxRuns,
		RunBudget: runBudget,
		Command:   buildClientCommand(m.cfg.Host, port, parallel, duration, mode, reverse),
		Mode:      mode,
		Reverse:   reverse,
		process:   process,
		events:    events,
	}
	session.timer = time.AfterFunc(ttl, func() { _ = m.release(req.SessionID, true, "ttl_expired") })

	m.mu.Lock()
	delete(m.reservations, req.SessionID)
	m.sessions[req.SessionID] = session
	active := len(m.sessions)
	reserved := len(m.reservations)
	ports := m.activePortsLocked()
	m.mu.Unlock()
	logging.Infof("iperf open session=%s port=%d active=%d reserved=%d ports=%v max_parallel=%d max_duration=%d max_runs=%d run_budget=%d command=%q",
		req.SessionID, port, active, reserved, ports, m.cfg.MaxParallel, m.cfg.MaxDuration, maxRuns, runBudget, session.Command)

	go m.watch(req.SessionID, process)

	return *session, nil
}

func (m *Manager) Close(sessionID string) error {
	return m.release(sessionID, true, "closed_by_request")
}

func (m *Manager) watch(sessionID string, process Process) {
	_ = process.Wait()
	_ = m.release(sessionID, false, "process_exit")
}

func (m *Manager) release(sessionID string, kill bool, reason string) error {
	m.mu.Lock()
	session, ok := m.sessions[sessionID]
	if ok {
		delete(m.sessions, sessionID)
	}
	m.mu.Unlock()
	if !ok {
		return ErrNotFound
	}
	if session.timer != nil {
		session.timer.Stop()
	}
	if statsProvider, ok := session.process.(interface{ Stats() Stats }); ok {
		if stats := statsProvider.Stats(); stats.CloseReason != "" {
			reason = stats.CloseReason
		}
	}
	if session.events != nil {
		event := m.statusEventLocked(session, "closed")
		event.CloseReason = reason
		session.events.publish(event)
		session.events.close()
	}
	if kill {
		return session.process.Kill()
	}
	return nil
}

func (m *Manager) Active() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}

func (m *Manager) Subscribe(sessionID string) (<-chan Event, func(), error) {
	m.mu.Lock()
	session, ok := m.sessions[sessionID]
	if !ok || session.events == nil {
		m.mu.Unlock()
		return nil, nil, ErrNotFound
	}
	ch, cancel, ok := session.events.subscribe()
	status := m.statusEventLocked(session, "status")
	m.mu.Unlock()
	if !ok {
		return nil, nil, ErrNotFound
	}
	session.events.publish(status)
	session.events.publish(Event{
		Type:      "debug",
		SessionID: session.SessionID,
		Port:      session.Port,
		Line:      fmt.Sprintf("server listening: %s:%d", session.Host, session.Port),
		At:        time.Now().Unix(),
	})
	return ch, cancel, nil
}

func (m *Manager) Status(sessionID string) (Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	session, ok := m.sessions[sessionID]
	if !ok {
		return Event{}, ErrNotFound
	}
	return m.statusEventLocked(session, "status"), nil
}

func (m *Manager) statusEventLocked(session *Session, eventType string) Event {
	stats := Stats{}
	if statsProvider, ok := session.process.(interface{ Stats() Stats }); ok {
		stats = statsProvider.Stats()
	}
	remainingSeconds := int(time.Until(session.ExpiresAt).Seconds())
	if remainingSeconds < 0 {
		remainingSeconds = 0
	}
	return Event{
		Type:             eventType,
		SessionID:        session.SessionID,
		Port:             session.Port,
		Command:          session.Command,
		Mode:             eventMode(stats),
		Reverse:          eventReverse(stats),
		RemainingSeconds: remainingSeconds,
		RemainingRuns:    maxInt(session.MaxRuns-stats.Attempts, 0),
		RunsUsed:         stats.Attempts,
		MaxRuns:          session.MaxRuns,
		CloseReason:      stats.CloseReason,
		At:               time.Now().Unix(),
	}
}

func eventMode(stats Stats) string {
	if stats.ClientSeen {
		return stats.Mode
	}
	return ""
}

func eventReverse(stats Stats) bool {
	if stats.ClientSeen {
		return stats.Reverse
	}
	return false
}

func (m *Manager) releaseReservation(sessionID string) {
	m.mu.Lock()
	delete(m.reservations, sessionID)
	m.mu.Unlock()
}

func (m *Manager) pickPortLocked() (int, error) {
	if m.cfg.PortMin >= m.cfg.PortMax {
		if m.portInUseLocked(m.cfg.PortMin) {
			return 0, ErrLimit
		}
		return m.cfg.PortMin, nil
	}
	size := m.cfg.PortMax - m.cfg.PortMin + 1
	startValue, err := crand.Int(crand.Reader, big.NewInt(int64(size)))
	if err != nil {
		return 0, err
	}
	start := int(startValue.Int64())
	for offset := 0; offset < size; offset++ {
		port := m.cfg.PortMin + ((start + offset) % size)
		if !m.portInUseLocked(port) {
			return port, nil
		}
	}
	return 0, ErrLimit
}

func (m *Manager) portInUseLocked(port int) bool {
	for _, session := range m.sessions {
		if session.Port == port {
			return true
		}
	}
	for _, reservedPort := range m.reservations {
		if reservedPort == port {
			return true
		}
	}
	return false
}

func (m *Manager) activePortsLocked() []int {
	ports := make([]int, 0, len(m.sessions)+len(m.reservations))
	for _, session := range m.sessions {
		ports = append(ports, session.Port)
	}
	for _, port := range m.reservations {
		ports = append(ports, port)
	}
	return ports
}

func clamp(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func normalizeMode(mode, direction string, reverse bool) (string, bool, error) {
	switch strings.ToLower(strings.TrimSpace(direction)) {
	case "reverse", "r":
		reverse = true
	}
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "tcp":
		return "tcp", reverse, nil
	case "udp":
		return "udp", reverse, nil
	case "reverse", "r":
		return "tcp", true, nil
	default:
		return "", false, ErrBadRequest
	}
}

func buildClientCommand(host string, port, parallel, duration int, mode string, reverse bool) string {
	args := []string{"iperf3"}
	if mode == "udp" {
		args = append(args, "-u")
	}
	args = append(args, "-c", host, "-p", fmt.Sprint(port), "-P", fmt.Sprint(parallel), "-t", fmt.Sprint(duration))
	if reverse {
		args = append(args, "-R")
	}
	return strings.Join(args, " ")
}

func serverArgs(port int) []string {
	return []string{"-s", "-p", fmt.Sprint(port), "--forceflush", "-d"}
}

func startIperfServer(_ context.Context, iperfPath string, port, maxRuns, runBudget, maxParallel, maxDuration int, emit func(Event)) (Process, error) {
	if iperfPath == "" {
		iperfPath = "iperf3"
	}
	cmd := exec.Command(iperfPath, serverArgs(port)...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	process := &execIperfProcess{
		cmd:     cmd,
		limiter: newIperfRunLimiter(port, maxRuns, runBudget, maxParallel, maxDuration, emit),
		emit:    emit,
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	process.watchOutput(stdout)
	process.watchOutput(stderr)
	return process, nil
}

type execIperfProcess struct {
	cmd     *exec.Cmd
	limiter *iperfRunLimiter
	emit    func(Event)
	kill    sync.Once
	killErr error
}

func (p *execIperfProcess) Kill() error {
	p.kill.Do(func() {
		p.killErr = p.killProcess()
	})
	return p.killErr
}

func (p *execIperfProcess) killProcess() error {
	if p.cmd.Process == nil {
		return nil
	}
	err := p.cmd.Process.Kill()
	if errors.Is(err, os.ErrProcessDone) {
		return nil
	}
	return err
}

func (p *execIperfProcess) Wait() error {
	return p.cmd.Wait()
}

func (p *execIperfProcess) Stats() Stats {
	return p.limiter.Stats()
}

func (p *execIperfProcess) watchOutput(reader io.Reader) {
	go func() {
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 0, 64*1024), maxIperfOutputLineBytes)
		for scanner.Scan() {
			line := scanner.Text()
			if p.limiter.Observe(line) {
				_ = p.Kill()
				return
			}
			if p.emit != nil {
				if formatted, ok := formatIperfServerLine(line); ok {
					p.emit(Event{Type: "output", Line: formatted})
				} else {
					p.emit(Event{Type: "debug", Line: line})
				}
			}
		}
		if err := scanner.Err(); err != nil && p.emit != nil {
			p.emit(Event{Type: "debug", Line: "iperf output read error"})
		}
	}()
}

type iperfRunLimiter struct {
	maxRuns        int
	runBudget      int
	maxParallel    int
	maxDuration    int
	port           int
	attempts       atomic.Int32
	runSpend       atomic.Int32
	currentCost    atomic.Int32
	closeReason    atomic.Value
	clientSeen     atomic.Bool
	lastReverse    atomic.Bool
	lastMode       atomic.Value
	emit           func(Event)
	parameterLock  sync.Mutex
	collecting     bool
	parameterJSON  []string
	parameterBytes int
	jsonDepth      int
}

// Bounds on the iperf3 control-connection "get_parameters" JSON we buffer. A
// well-behaved client sends a small single-line object; these caps stop a
// malicious or broken client from growing the buffer without limit (e.g. by
// sending many "{" without ever closing the object).
const (
	maxIperfParameterLines  = 64
	maxIperfParameterBytes  = 8 << 10 // 8 KiB
	maxIperfOutputLineBytes = 1 << 20 // 1 MiB
)

type iperfClientParameters struct {
	TCP           bool  `json:"tcp"`
	UDP           bool  `json:"udp"`
	Reverse       bool  `json:"reverse"`
	Bidirectional bool  `json:"bidir"`
	Time          int   `json:"time"`
	Num           int64 `json:"num"`
	BlockCount    int64 `json:"blockcount"`
	Parallel      int   `json:"parallel"`
}

func newIperfRunLimiter(port, maxRuns, runBudget, maxParallel, maxDuration int, emit ...func(Event)) *iperfRunLimiter {
	if maxParallel <= 0 {
		maxParallel = 1
	}
	limiter := &iperfRunLimiter{
		maxRuns:     maxRuns,
		runBudget:   runBudget,
		maxParallel: maxParallel,
		maxDuration: maxDuration,
		port:        port,
	}
	if len(emit) > 0 {
		limiter.emit = emit[0]
	}
	limiter.currentCost.Store(int32(maxParallel))
	return limiter
}

func (l *iperfRunLimiter) Observe(line string) bool {
	if l.rejectsClientParameters(line) {
		return true
	}
	return l.closesAfterRunCompletion(line)
}

func (l *iperfRunLimiter) rejectsClientParameters(line string) bool {
	params, ok, invalid := l.collectClientParameters(line)
	if invalid {
		l.setCloseReason("invalid_client_parameters")
		l.publish(Event{Type: "closed", CloseReason: "invalid_client_parameters"})
		logging.Infof("iperf close port=%d reason=invalid_client_parameters", l.port)
		return true
	}
	if !ok {
		return false
	}
	parallel := params.Parallel
	if parallel <= 0 {
		parallel = 1
	}
	logging.Infof("iperf params port=%d parallel=%d time=%d udp=%t reverse=%t bidir=%t num=%d blockcount=%d max_parallel=%d max_duration=%d",
		l.port, parallel, params.Time, params.UDP, params.Reverse, params.Bidirectional, params.Num, params.BlockCount, l.maxParallel, l.maxDuration)
	if parallel > l.maxParallel {
		l.setCloseReason("parallel_limit")
		l.publish(Event{Type: "output", Line: formatIperfRejectionSummary("parallel_limit", params, parallel, l.maxParallel, l.maxDuration)})
		l.publish(Event{Type: "closed", CloseReason: "parallel_limit"})
		logging.Infof("iperf close port=%d reason=parallel_limit parallel=%d max_parallel=%d", l.port, parallel, l.maxParallel)
		return true
	}
	// A client-specified duration must be within [1, maxDuration]. A value <= 0
	// (including a bare `time=0`, which iperf3 interprets as its own default
	// 10s) is not a valid request and would otherwise slip past the upper-bound
	// check while actually running longer than a small maxDuration.
	if params.Time <= 0 {
		l.setCloseReason("duration_limit")
		l.publish(Event{Type: "output", Line: formatIperfRejectionSummary("duration_limit", params, parallel, l.maxParallel, l.maxDuration)})
		l.publish(Event{Type: "closed", CloseReason: "duration_limit"})
		logging.Infof("iperf close port=%d reason=duration_limit time=%d max_duration=%d", l.port, params.Time, l.maxDuration)
		return true
	}
	if l.maxDuration > 0 && params.Time > l.maxDuration {
		l.setCloseReason("duration_limit")
		l.publish(Event{Type: "output", Line: formatIperfRejectionSummary("duration_limit", params, parallel, l.maxParallel, l.maxDuration)})
		l.publish(Event{Type: "closed", CloseReason: "duration_limit"})
		logging.Infof("iperf close port=%d reason=duration_limit time=%d max_duration=%d", l.port, params.Time, l.maxDuration)
		return true
	}
	if params.Num > 0 || params.BlockCount > 0 || params.Bidirectional {
		l.setCloseReason("unsupported_mode")
		l.publish(Event{Type: "output", Line: formatIperfRejectionSummary("unsupported_mode", params, parallel, l.maxParallel, l.maxDuration)})
		l.publish(Event{Type: "closed", CloseReason: "unsupported_mode"})
		logging.Infof("iperf close port=%d reason=unsupported_mode num=%d blockcount=%d bidir=%t",
			l.port, params.Num, params.BlockCount, params.Bidirectional)
		return true
	}
	l.currentCost.Store(int32(parallel))
	mode := modeFromClientParameters(params)
	l.lastMode.Store(mode)
	l.lastReverse.Store(params.Reverse)
	l.clientSeen.Store(true)
	attempts := int(l.attempts.Add(1))
	spend := int(l.runSpend.Add(int32(parallel)))
	closed := (l.maxRuns > 0 && attempts > l.maxRuns) || (l.runBudget > 0 && spend > l.runBudget)
	logging.Infof("iperf attempt port=%d attempts=%d spend=%d remaining_runs=%d max_runs=%d run_budget=%d parallel=%d",
		l.port, attempts, spend, maxInt(l.maxRuns-attempts, 0), l.maxRuns, l.runBudget, parallel)
	l.publish(Event{
		Type:          "status",
		Port:          l.port,
		Mode:          mode,
		Reverse:       params.Reverse,
		RemainingRuns: maxInt(l.maxRuns-attempts, 0),
		RunsUsed:      attempts,
		MaxRuns:       l.maxRuns,
	})
	if closed {
		l.setCloseReason("run_limit")
		l.publish(Event{Type: "output", Line: fmt.Sprintf("client rejected: run_limit attempts=%d max_runs=%d spend=%d run_budget=%d", attempts, l.maxRuns, spend, l.runBudget)})
		l.publish(Event{Type: "closed", CloseReason: "run_limit"})
		logging.Infof("iperf close port=%d reason=run_limit attempts=%d spend=%d max_runs=%d run_budget=%d last_parallel=%d",
			l.port, attempts, spend, l.maxRuns, l.runBudget, parallel)
	}
	if !closed {
		l.publish(Event{Type: "debug", Line: formatIperfAcceptedSummary(params, parallel)})
	}
	return closed
}

func (l *iperfRunLimiter) closesAfterRunCompletion(line string) bool {
	if !isIperfRunTerminalLine(line) {
		return false
	}
	attempts := int(l.attempts.Load())
	spend := int(l.runSpend.Load())
	if !l.reachedRunLimit(attempts, spend) {
		return false
	}
	l.setCloseReason("run_limit")
	if formatted, ok := formatIperfServerLine(line); ok && formatted != "" {
		l.publish(Event{Type: "output", Line: formatted})
	}
	l.publish(Event{Type: "closed", CloseReason: "run_limit"})
	logging.Infof("iperf close port=%d reason=run_limit attempts=%d spend=%d max_runs=%d run_budget=%d",
		l.port, attempts, spend, l.maxRuns, l.runBudget)
	return true
}

func (l *iperfRunLimiter) reachedRunLimit(attempts, spend int) bool {
	return (l.maxRuns > 0 && attempts >= l.maxRuns) || (l.runBudget > 0 && spend >= l.runBudget)
}

func (l *iperfRunLimiter) setCloseReason(reason string) {
	l.closeReason.Store(reason)
}

func (l *iperfRunLimiter) publish(event Event) {
	if l.emit == nil {
		return
	}
	if event.Port == 0 {
		event.Port = l.port
	}
	l.emit(event)
}

func (l *iperfRunLimiter) Stats() Stats {
	stats := Stats{
		Attempts: int(l.attempts.Load()),
		Spend:    int(l.runSpend.Load()),
	}
	if reason, ok := l.closeReason.Load().(string); ok {
		stats.CloseReason = reason
	}
	if mode, ok := l.lastMode.Load().(string); ok {
		stats.Mode = mode
	}
	stats.Reverse = l.lastReverse.Load()
	stats.ClientSeen = l.clientSeen.Load()
	return stats
}

func (l *iperfRunLimiter) collectClientParameters(line string) (iperfClientParameters, bool, bool) {
	l.parameterLock.Lock()
	defer l.parameterLock.Unlock()

	if strings.Contains(line, "get_parameters:") {
		l.collecting = true
		l.parameterJSON = l.parameterJSON[:0]
		l.parameterBytes = 0
		l.jsonDepth = 0
		return iperfClientParameters{}, false, false
	}
	if !l.collecting {
		return iperfClientParameters{}, false, false
	}

	trimmed := strings.TrimSpace(line)
	if trimmed == "" && len(l.parameterJSON) == 0 {
		return iperfClientParameters{}, false, false
	}
	l.parameterJSON = append(l.parameterJSON, trimmed)
	l.parameterBytes += len(trimmed)
	l.jsonDepth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
	if len(l.parameterJSON) > maxIperfParameterLines || l.parameterBytes > maxIperfParameterBytes {
		l.collecting = false
		l.parameterJSON = l.parameterJSON[:0]
		l.parameterBytes = 0
		l.jsonDepth = 0
		return iperfClientParameters{}, false, true
	}
	if l.jsonDepth > 0 || len(l.parameterJSON) == 0 {
		return iperfClientParameters{}, false, false
	}

	l.collecting = false
	var params iperfClientParameters
	if err := json.Unmarshal([]byte(strings.Join(l.parameterJSON, "\n")), &params); err != nil {
		return iperfClientParameters{}, false, true
	}
	return params, true, false
}

func formatIperfAcceptedSummary(params iperfClientParameters, parallel int) string {
	mode := modeFromClientParameters(params)
	return fmt.Sprintf("client accepted: %s parallel=%d duration=%ds reverse=%t", mode, parallel, params.Time, params.Reverse)
}

func modeFromClientParameters(params iperfClientParameters) string {
	if params.UDP {
		return "udp"
	}
	return "tcp"
}

func formatIperfRejectionSummary(reason string, params iperfClientParameters, parallel, maxParallel, maxDuration int) string {
	switch reason {
	case "parallel_limit":
		return fmt.Sprintf("client rejected: parallel_limit requested_parallel=%d max_parallel=%d", parallel, maxParallel)
	case "duration_limit":
		return fmt.Sprintf("client rejected: duration_limit requested_duration=%ds max_duration=%ds", params.Time, maxDuration)
	case "unsupported_mode":
		return "client rejected: unsupported_mode bidirectional/byte-count modes are disabled"
	default:
		return fmt.Sprintf("client rejected: %s", reason)
	}
}

func formatIperfServerLine(line string) (string, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return "", false
	}
	if strings.HasPrefix(trimmed, "iperf3: interrupt") {
		return "cancelled: " + strings.TrimPrefix(trimmed, "iperf3: interrupt - "), true
	}
	if trimmed == "iperf3: the client has terminated" {
		return "cancelled: the client has terminated", true
	}
	if strings.HasPrefix(trimmed, "iperf3: error") {
		return "error: " + strings.TrimPrefix(trimmed, "iperf3: error - "), true
	}
	if isIperfDebugLine(trimmed) {
		return "", false
	}
	if strings.Contains(trimmed, "Server listening on") {
		return "", false
	}
	if strings.Contains(trimmed, "Accepted connection from") {
		return strings.Replace(trimmed, "Accepted connection from", "accepted connection from", 1), true
	}
	if strings.Contains(trimmed, "connected to") {
		return trimmed, true
	}
	if strings.Contains(trimmed, "bits/sec") || strings.Contains(trimmed, "Bytes") {
		return trimmed, true
	}
	if strings.Contains(trimmed, "sender") || strings.Contains(trimmed, "receiver") {
		return trimmed, true
	}
	if strings.Contains(trimmed, "Test Complete") {
		return "---------- RUN COMPLETE ----------", true
	}
	if strings.Contains(trimmed, "Summary Results") {
		return "", false
	}
	if strings.Trim(trimmed, "-") == "" && len(trimmed) >= 8 {
		return "----", true
	}
	return "", false
}

func isIperfRunTerminalLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "iperf3: interrupt") || strings.Contains(trimmed, "Test Complete") || strings.Contains(trimmed, "IPERF_DONE")
}

func isIperfDebugLine(trimmed string) bool {
	if trimmed == "get_parameters:" || trimmed == "{" || trimmed == "}" || strings.HasPrefix(trimmed, `"`) {
		return true
	}
	dropPatterns := []string{
		"Late receive",
		"State change",
		"Thread ",
		"tcpi_",
		"interval_len",
		"interval forces keep",
		"get_results",
		"send_results",
		"send_parameters",
		"JSON_write",
		"iperf_json_finish",
	}
	for _, pattern := range dropPatterns {
		if strings.Contains(trimmed, pattern) {
			return true
		}
	}
	return false
}
