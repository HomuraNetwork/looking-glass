package iperf

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestManagerOpensAndClosesSingleSession(t *testing.T) {
	started := 0
	manager := NewManager(Config{
		Host:        "testnode01.lgtest-node.example",
		PortMin:     31000,
		PortMax:     31000,
		TTL:         time.Minute,
		ActiveLimit: 1,
		MaxDuration: 30,
		MaxParallel: 4,
		StartServer: func(context.Context, int, int, int, int, int, func(Event)) (Process, error) {
			started++
			return newBlockingProcess(), nil
		},
		ConfirmListen: func(context.Context, int) error { return nil },
	})

	session, err := manager.Open(context.Background(), OpenRequest{
		SessionID: "ipf_test",
		Duration:  10,
		Parallel:  4,
		TTL:       30,
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.Port != 31000 || started != 1 {
		t.Fatalf("session=%#v started=%d", session, started)
	}
	reused, err := manager.Open(context.Background(), OpenRequest{SessionID: "ipf_test", Duration: 10, Parallel: 1, TTL: 30})
	if err != nil {
		t.Fatalf("reuse err = %v", err)
	}
	if !reused.Reused || reused.SessionID != "ipf_test" {
		t.Fatalf("reused session = %#v", reused)
	}
	if err := manager.Close("ipf_test"); err != nil {
		t.Fatal(err)
	}
	if manager.Active() != 0 {
		t.Fatalf("active = %d", manager.Active())
	}
}

func TestManagerClampsDurationParallelAndTTL(t *testing.T) {
	process := newBlockingProcess()
	manager := NewManager(Config{
		Host:          "testnode01.lgtest-node.example",
		PortMin:       32000,
		PortMax:       32000,
		TTL:           2 * time.Minute,
		ActiveLimit:   1,
		MaxDuration:   30,
		MaxParallel:   4,
		StartServer:   func(context.Context, int, int, int, int, int, func(Event)) (Process, error) { return process, nil },
		ConfirmListen: func(context.Context, int) error { return nil },
	})

	session, err := manager.Open(context.Background(), OpenRequest{SessionID: "ipf_clamp", Duration: 300, Parallel: 99, TTL: 300})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close(session.SessionID)
	if session.Command != "iperf3 -c testnode01.lgtest-node.example -p 32000 -P 4 -t 30" {
		t.Fatalf("command = %q", session.Command)
	}
	if session.ExpiresAt.After(time.Now().Add(121 * time.Second)) {
		t.Fatalf("expires_at not clamped: %s", session.ExpiresAt)
	}
}

func TestManagerUsesGlobalCapsForServerSideInputValidation(t *testing.T) {
	process := newBlockingProcess()
	allowedParallel := 0
	allowedDuration := 0
	manager := NewManager(Config{
		Host:        "testnode01.lgtest-node.example",
		PortMin:     32100,
		PortMax:     32100,
		MaxDuration: 40,
		MaxParallel: 10,
		StartServer: func(_ context.Context, _ int, _ int, _ int, maxParallel, maxDuration int, _ func(Event)) (Process, error) {
			allowedParallel = maxParallel
			allowedDuration = maxDuration
			return process, nil
		},
		ConfirmListen: func(context.Context, int) error { return nil },
	})

	session, err := manager.Open(context.Background(), OpenRequest{SessionID: "ipf_caps", Duration: 1, Parallel: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close(session.SessionID)
	if session.Command != "iperf3 -c testnode01.lgtest-node.example -p 32100 -P 1 -t 1" {
		t.Fatalf("command = %q", session.Command)
	}
	if allowedParallel != 10 || allowedDuration != 40 {
		t.Fatalf("server caps parallel=%d duration=%d, want 10/40", allowedParallel, allowedDuration)
	}
}

func TestManagerBuildsUDPReverseCommandAndThreeMinuteWindow(t *testing.T) {
	process := newBlockingProcess()
	manager := NewManager(Config{
		Host:          "testnode01.lgtest-node.example",
		PortMin:       35000,
		PortMax:       35000,
		TTL:           3 * time.Minute,
		ActiveLimit:   1,
		MaxDuration:   40,
		MaxParallel:   10,
		MaxRuns:       4,
		RunBudget:     200,
		StartServer:   func(context.Context, int, int, int, int, int, func(Event)) (Process, error) { return process, nil },
		ConfirmListen: func(context.Context, int) error { return nil },
	})

	session, err := manager.Open(context.Background(), OpenRequest{
		SessionID: "ipf_udp_reverse",
		Mode:      "udp",
		Reverse:   true,
		Duration:  300,
		Parallel:  100,
		TTL:       180,
		MaxRuns:   4,
		RunBudget: 200,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close(session.SessionID)
	if session.Command != "iperf3 -u -c testnode01.lgtest-node.example -p 35000 -P 10 -t 40 -R" {
		t.Fatalf("command = %q", session.Command)
	}
	if session.Mode != "udp" || !session.Reverse {
		t.Fatalf("session flow mode=%q reverse=%t", session.Mode, session.Reverse)
	}
	if session.ExpiresAt.After(time.Now().Add(181 * time.Second)) {
		t.Fatalf("expires_at not clamped to three minutes: %s", session.ExpiresAt)
	}
	if session.MaxRuns != 4 {
		t.Fatalf("max runs = %d", session.MaxRuns)
	}
	if session.RunBudget != 200 {
		t.Fatalf("run budget = %d", session.RunBudget)
	}
}

func TestManagerOpensDistinctSessionsUntilActiveLimit(t *testing.T) {
	started := 0
	manager := NewManager(Config{
		Host:        "testnode01.lgtest-node.example",
		PortMin:     36000,
		PortMax:     36001,
		TTL:         3 * time.Minute,
		ActiveLimit: 2,
		StartServer: func(context.Context, int, int, int, int, int, func(Event)) (Process, error) {
			started++
			return newBlockingProcess(), nil
		},
		ConfirmListen: func(context.Context, int) error { return nil },
	})

	first, err := manager.Open(context.Background(), OpenRequest{SessionID: "ipf_first", Duration: 10, Parallel: 1})
	if err != nil {
		t.Fatal(err)
	}
	second, err := manager.Open(context.Background(), OpenRequest{SessionID: "ipf_second", Duration: 40, Parallel: 10})
	if err != nil {
		t.Fatal(err)
	}
	if started != 2 {
		t.Fatalf("started = %d", started)
	}
	if second.Reused || second.SessionID == first.SessionID || second.Port == first.Port {
		t.Fatalf("second session = %#v, first = %#v", second, first)
	}
	third, err := manager.Open(context.Background(), OpenRequest{SessionID: "ipf_third", Duration: 10, Parallel: 1})
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("third err = %v, want %v", err, ErrLimit)
	}
	if third.SessionID != "" {
		t.Fatalf("third session = %#v", third)
	}
}

func TestManagerStartServerOutlivesOpenRequestContext(t *testing.T) {
	startedWith := make(chan context.Context, 1)
	manager := NewManager(Config{
		Host:        "testnode01.lgtest-node.example",
		PortMin:     33000,
		PortMax:     33000,
		TTL:         time.Minute,
		ActiveLimit: 1,
		StartServer: func(ctx context.Context, _ int, _ int, _ int, _ int, _ int, _ func(Event)) (Process, error) {
			startedWith <- ctx
			return newBlockingProcess(), nil
		},
		ConfirmListen: func(context.Context, int) error { return nil },
	})

	ctx, cancel := context.WithCancel(context.Background())
	if _, err := manager.Open(ctx, OpenRequest{SessionID: "ipf_ctx", Duration: 10, Parallel: 1, TTL: 30}); err != nil {
		t.Fatal(err)
	}
	cancel()

	startCtx := <-startedWith
	select {
	case <-startCtx.Done():
		t.Fatal("iperf server context was canceled with the control request")
	default:
	}
}

func TestManagerReleasesSessionWhenProcessExits(t *testing.T) {
	process := newBlockingProcess()
	manager := NewManager(Config{
		Host:          "testnode01.lgtest-node.example",
		PortMin:       34000,
		PortMax:       34000,
		TTL:           time.Minute,
		ActiveLimit:   1,
		StartServer:   func(context.Context, int, int, int, int, int, func(Event)) (Process, error) { return process, nil },
		ConfirmListen: func(context.Context, int) error { return nil },
	})

	if _, err := manager.Open(context.Background(), OpenRequest{SessionID: "ipf_exit", Duration: 10, Parallel: 1, TTL: 30}); err != nil {
		t.Fatal(err)
	}
	process.finish()
	waitForActive(t, manager, 0)
}

func TestSubscribePublishesServerListeningDebug(t *testing.T) {
	process := newBlockingProcess()
	manager := NewManager(Config{
		Host:          "testnode01.lgtest-node.example",
		PortMin:       34900,
		PortMax:       34900,
		StartServer:   func(context.Context, int, int, int, int, int, func(Event)) (Process, error) { return process, nil },
		ConfirmListen: func(context.Context, int) error { return nil },
	})
	session, err := manager.Open(context.Background(), OpenRequest{
		SessionID: "ipf_listen",
		Mode:      "udp",
		Reverse:   true,
		Duration:  10,
		Parallel:  4,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close(session.SessionID)
	events, cancel, err := manager.Subscribe(session.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	initialStatus := <-events
	if initialStatus.Type != "status" {
		t.Fatalf("initial status = %#v", initialStatus)
	}
	if initialStatus.Mode != "" || initialStatus.Reverse {
		t.Fatalf("initial status must not expose generated client flow before a client connects: %#v", initialStatus)
	}
	var event Event
	select {
	case event = <-events:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timed out waiting for server listening output")
	}
	if event.Type != "debug" || event.Line != "server listening: testnode01.lgtest-node.example:34900" {
		t.Fatalf("event = %#v", event)
	}
}

func TestIperfRunLimiterClosesWhenLastAllowedRunCompletes(t *testing.T) {
	var events []Event
	limiter := newIperfRunLimiter(35000, 4, 200, 10, 40, func(event Event) {
		events = append(events, event)
	})
	for attempt := 1; attempt <= 3; attempt++ {
		if observeClientParameters(limiter, 10, 10) {
			t.Fatalf("attempt %d closed too early", attempt)
		}
		if limiter.Observe("Test Complete. Summary Results:") {
			t.Fatalf("attempt %d completion closed too early", attempt)
		}
	}
	if observeClientParameters(limiter, 10, 10) {
		t.Fatal("fourth attempt should be allowed to run")
	}
	if !limiter.Observe("Test Complete. Summary Results:") {
		t.Fatal("fourth completion should close the session")
	}
	if stats := limiter.Stats(); stats.CloseReason != "run_limit" {
		t.Fatalf("stats = %#v", stats)
	}
	if len(events) < 2 {
		t.Fatalf("events = %#v", events)
	}
	if events[len(events)-2].Type != "output" || events[len(events)-2].Line != "---------- RUN COMPLETE ----------" {
		t.Fatalf("penultimate event = %#v", events[len(events)-2])
	}
	if events[len(events)-1].Type != "closed" || events[len(events)-1].CloseReason != "run_limit" {
		t.Fatalf("last event = %#v", events[len(events)-1])
	}
}

func TestIperfRunLimiterClosesWhenLastCancelledRunReachesDoneState(t *testing.T) {
	limiter := newIperfRunLimiter(35000, 4, 200, 10, 40)
	for attempt := 1; attempt <= 3; attempt++ {
		if observeClientParameters(limiter, 1, 10) {
			t.Fatalf("attempt %d closed too early", attempt)
		}
		if limiter.Observe("iperf3: the client has terminated") {
			t.Fatalf("attempt %d cancel line closed too early", attempt)
		}
		if limiter.Observe("State change: State set to 16-IPERF_DONE (from 12-CLIENT_TERMINATE)") {
			t.Fatalf("attempt %d done state closed too early", attempt)
		}
	}
	if observeClientParameters(limiter, 1, 10) {
		t.Fatal("fourth cancelled attempt should be allowed to run")
	}
	if limiter.Observe("iperf3: the client has terminated") {
		t.Fatal("fourth cancel line should wait for summary output")
	}
	if !limiter.Observe("State change: State set to 16-IPERF_DONE (from 12-CLIENT_TERMINATE)") {
		t.Fatal("fourth cancelled done state should close the session")
	}
}

func TestIperfRunLimiterStillRejectsRunThatStartsAfterLimit(t *testing.T) {
	limiter := newIperfRunLimiter(35000, 4, 200, 10, 40)
	for attempt := 1; attempt <= 4; attempt++ {
		if observeClientParameters(limiter, 10, 10) {
			t.Fatalf("attempt %d closed too early", attempt)
		}
	}
	if !observeClientParameters(limiter, 10, 10) {
		t.Fatal("fifth attempt should close the session")
	}
}

func TestIperfRunLimiterAllowsP10TwentyTimesByBudget(t *testing.T) {
	limiter := newIperfRunLimiter(35000, 100, 200, 10, 40)
	for attempt := 1; attempt <= 19; attempt++ {
		if observeClientParameters(limiter, 10, 10) {
			t.Fatalf("attempt %d closed too early", attempt)
		}
		if limiter.Observe("Test Complete. Summary Results:") {
			t.Fatalf("attempt %d completion closed too early", attempt)
		}
	}
	if observeClientParameters(limiter, 10, 10) {
		t.Fatal("twentieth P10 attempt should be allowed to run")
	}
	if !limiter.Observe("Test Complete. Summary Results:") {
		t.Fatal("twentieth P10 completion should close the session at budget 200")
	}
}

func TestIperfRunLimiterRejectsOversizedClientParameters(t *testing.T) {
	limiter := newIperfRunLimiter(35000, 4, 200, 10, 40)
	if limiter.Observe("get_parameters:") {
		t.Fatal("get_parameters header should not close the session")
	}
	closed := false
	// A malicious client never closes the JSON object: each line opens a new
	// brace so jsonDepth stays positive. The line/byte caps must close it
	// rather than letting the buffer grow without bound.
	for i := 0; i < maxIperfParameterLines+5 && !closed; i++ {
		closed = limiter.Observe("{")
	}
	if !closed {
		t.Fatal("oversized client parameters should close the session")
	}
	if got := limiter.Stats().CloseReason; got != "invalid_client_parameters" {
		t.Fatalf("close reason = %q, want invalid_client_parameters", got)
	}
	if len(limiter.parameterJSON) != 0 {
		t.Fatalf("parameter buffer should be reset after rejection, got %d lines", len(limiter.parameterJSON))
	}
}

func TestIperfRunLimiterRejectsOutOfRangeClientParameters(t *testing.T) {
	cases := []struct {
		name    string
		observe func(*iperfRunLimiter) bool
	}{
		{
			name: "parallel exceeds the configured limit",
			observe: func(limiter *iperfRunLimiter) bool {
				return observeClientParameters(limiter, 30, 10)
			},
		},
		{
			name: "duration exceeds the configured limit",
			observe: func(limiter *iperfRunLimiter) bool {
				return observeClientParameters(limiter, 1, 41)
			},
		},
		{
			name: "zero duration would invoke iperf default",
			observe: func(limiter *iperfRunLimiter) bool {
				lines := []string{
					"get_parameters:", "{", "\t\"tcp\":\ttrue,", "\t\"parallel\":\t1,", "\t\"time\":\t0,", "}",
				}
				for _, line := range lines {
					if limiter.Observe(line) {
						return true
					}
				}
				return false
			},
		},
	}
	for _, tc := range cases {
		limiter := newIperfRunLimiter(35000, 4, 20, 10, 40)
		if !tc.observe(limiter) {
			t.Errorf("%s should close the server", tc.name)
		}
	}
}

func TestIperfOutputFormatterFiltersDebugNoise(t *testing.T) {
	dropped := []string{
		"get_parameters:",
		`	"tcp":	true,`,
		"Late receive, state = 14-DISPLAY_RESULTS",
		"State change: TEST_RUNNING -> DISPLAY_RESULTS",
		"tcpi_snd_cwnd 10",
		"interval_len 1.00",
	}
	for _, line := range dropped {
		if formatted, ok := formatIperfServerLine(line); ok {
			t.Fatalf("line %q formatted as %q, want dropped", line, formatted)
		}
	}

	formatted, ok := formatIperfServerLine("[  5]   0.00-1.00   sec   112 MBytes   941 Mbits/sec")
	if !ok || formatted != "[  5]   0.00-1.00   sec   112 MBytes   941 Mbits/sec" {
		t.Fatalf("formatted = %q ok=%t", formatted, ok)
	}
}

func TestIperfRunLimiterPublishesAcceptedClientSummaryAsDebug(t *testing.T) {
	var debugLines []string
	var outputLines []string
	limiter := newIperfRunLimiter(35000, 4, 200, 10, 40, func(event Event) {
		if event.Type == "debug" {
			debugLines = append(debugLines, event.Line)
		}
		if event.Type == "output" {
			outputLines = append(outputLines, event.Line)
		}
	})
	if observeClientParameters(limiter, 10, 40) {
		t.Fatal("first allowed attempt should not close the session")
	}
	if len(outputLines) != 0 {
		t.Fatalf("accepted client summary must not be user output: %#v", outputLines)
	}
	if len(debugLines) != 1 || debugLines[0] != "client accepted: tcp parallel=10 duration=40s reverse=false" {
		t.Fatalf("debug lines = %#v", debugLines)
	}
}

func TestIperfRunLimiterRecordsActualClientFlow(t *testing.T) {
	var events []Event
	limiter := newIperfRunLimiter(35000, 4, 200, 10, 40, func(event Event) {
		events = append(events, event)
	})
	if observeClientParametersWith(limiter, iperfClientParameters{UDP: true, Reverse: true, Parallel: 4, Time: 20}) {
		t.Fatal("first allowed attempt should not close the session")
	}
	stats := limiter.Stats()
	if !stats.ClientSeen || stats.Mode != "udp" || !stats.Reverse {
		t.Fatalf("stats = %#v", stats)
	}
	if len(events) == 0 {
		t.Fatal("expected status event")
	}
	var status Event
	for _, event := range events {
		if event.Type == "status" {
			status = event
			break
		}
	}
	if status.Mode != "udp" || !status.Reverse {
		t.Fatalf("status event = %#v", status)
	}
}

func TestIperfRunLimiterDoesNotCallRejectedClientAccepted(t *testing.T) {
	var lines []string
	limiter := newIperfRunLimiter(35000, 4, 200, 10, 40, func(event Event) {
		if event.Type == "output" {
			lines = append(lines, event.Line)
		}
	})
	if !observeClientParameters(limiter, 4, 103) {
		t.Fatal("over-duration client parameters should close the session")
	}
	if len(lines) != 1 {
		t.Fatalf("output lines = %#v", lines)
	}
	if strings.Contains(lines[0], "accepted") {
		t.Fatalf("rejected run must not be marked accepted: %q", lines[0])
	}
	if lines[0] != "client rejected: duration_limit requested_duration=103s max_duration=40s" {
		t.Fatalf("rejection line = %q", lines[0])
	}
}

func TestIperfOutputFormatterShowsCancelAndRunEnd(t *testing.T) {
	cancelled, ok := formatIperfServerLine("iperf3: interrupt - the client has terminated by signal Interrupt: 2")
	if !ok || !strings.Contains(cancelled, "cancelled:") {
		t.Fatalf("cancelled = %q ok=%t", cancelled, ok)
	}
	serverCancelled, ok := formatIperfServerLine("iperf3: the client has terminated")
	if !ok || serverCancelled != "cancelled: the client has terminated" {
		t.Fatalf("serverCancelled = %q ok=%t", serverCancelled, ok)
	}

	ended, ok := formatIperfServerLine("Test Complete. Summary Results:")
	if !ok || ended != "---------- RUN COMPLETE ----------" {
		t.Fatalf("ended = %q ok=%t", ended, ok)
	}
}

func TestManagerFiltersDebugEventsUnlessEnabled(t *testing.T) {
	process := newBlockingProcess()
	var emit func(Event)
	manager := NewManager(Config{
		Host:    "testnode01.lgtest-node.example",
		PortMin: 35100,
		PortMax: 35100,
		StartServer: func(_ context.Context, _ int, _ int, _ int, _ int, _ int, publish func(Event)) (Process, error) {
			emit = publish
			return process, nil
		},
		ConfirmListen: func(context.Context, int) error { return nil },
	})
	session, err := manager.Open(context.Background(), OpenRequest{SessionID: "ipf_no_debug", Duration: 10, Parallel: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close(session.SessionID)
	events, cancel, err := manager.Subscribe(session.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	<-events
	<-events

	emit(Event{Type: "debug", Line: "Late receive, state = 14-DISPLAY_RESULTS"})
	select {
	case event := <-events:
		t.Fatalf("received debug event while disabled: %#v", event)
	case <-time.After(20 * time.Millisecond):
	}

	emit(Event{Type: "output", Line: "accepted connection from 203.0.113.1"})
	event := <-events
	if event.Type != "output" {
		t.Fatalf("event = %#v", event)
	}
}

func TestManagerCanExposeDebugEventsWhenEnabled(t *testing.T) {
	process := newBlockingProcess()
	var emit func(Event)
	manager := NewManager(Config{
		Host:        "testnode01.lgtest-node.example",
		PortMin:     35101,
		PortMax:     35101,
		DebugOutput: true,
		StartServer: func(_ context.Context, _ int, _ int, _ int, _ int, _ int, publish func(Event)) (Process, error) {
			emit = publish
			return process, nil
		},
		ConfirmListen: func(context.Context, int) error { return nil },
	})
	session, err := manager.Open(context.Background(), OpenRequest{SessionID: "ipf_debug", Duration: 10, Parallel: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close(session.SessionID)
	events, cancel, err := manager.Subscribe(session.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	<-events
	<-events

	emit(Event{Type: "debug", Line: "Late receive, state = 14-DISPLAY_RESULTS"})
	event := <-events
	if event.Type != "debug" || event.Line == "" {
		t.Fatalf("event = %#v", event)
	}
}

func TestServerArgsUseReusableForceFlushedServer(t *testing.T) {
	args := serverArgs(31742)
	if strings.Join(args, " ") != "-s -p 31742 --forceflush -d" {
		t.Fatalf("server args = %#v", args)
	}
	for _, arg := range args {
		if arg == "-1" {
			t.Fatal("server args must not use one-off mode")
		}
	}
}

type blockingProcess struct {
	done chan struct{}
}

func newBlockingProcess() *blockingProcess {
	return &blockingProcess{done: make(chan struct{})}
}

func (p *blockingProcess) Kill() error {
	p.finish()
	return nil
}

func (p *blockingProcess) Wait() error {
	<-p.done
	return nil
}

func (p *blockingProcess) finish() {
	select {
	case <-p.done:
	default:
		close(p.done)
	}
}

func waitForActive(t *testing.T, manager *Manager, want int) {
	t.Helper()
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		if manager.Active() == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("active = %d, want %d", manager.Active(), want)
}

func observeClientParameters(limiter *iperfRunLimiter, parallel, duration int) bool {
	return observeClientParametersWith(limiter, iperfClientParameters{TCP: true, Parallel: parallel, Time: duration})
}

func observeClientParametersWith(limiter *iperfRunLimiter, params iperfClientParameters) bool {
	if !params.TCP && !params.UDP {
		params.TCP = true
	}
	if params.Parallel == 0 {
		params.Parallel = 1
	}
	if params.Time == 0 {
		params.Time = 10
	}
	lines := []string{
		"get_parameters:",
		"{",
		fmt.Sprintf(`	"tcp":	%t,`, params.TCP),
		fmt.Sprintf(`	"udp":	%t,`, params.UDP),
		fmt.Sprintf(`	"reverse":	%t,`, params.Reverse),
		fmt.Sprintf(`	"bidir":	%t,`, params.Bidirectional),
		fmt.Sprintf(`	"time":	%d,`, params.Time),
		fmt.Sprintf(`	"num":	%d,`, params.Num),
		fmt.Sprintf(`	"blockcount":	%d,`, params.BlockCount),
		fmt.Sprintf(`	"parallel":	%d,`, params.Parallel),
		`	"client_version":	"3.18"`,
		"}",
	}
	closed := false
	for _, line := range lines {
		closed = limiter.Observe(line)
	}
	return closed
}
