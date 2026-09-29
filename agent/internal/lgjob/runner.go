package lgjob

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unicode"

	"github.com/creack/pty"

	"hlg/internal/deps"
	"hlg/internal/guard"
	"hlg/internal/probe"
	"hlg/internal/token"
)

// Runner executes job tools. GuardPrivateIP enables the execute-time
// private-IP guard on the job target; the zero value fails safe (guard
// on). Set it to false only to honor an explicit bundle opt-out — the
// worker-side check remains regardless.
type Runner struct {
	GuardPrivateIP *bool
	// ResolveFunc is injectable for tests and specialized callers; nil uses
	// the system resolver.
	ResolveFunc guard.ResolveFunc
	// MaxOutputBytes caps total job output; 0 uses DefaultOutputLimit.
	MaxOutputBytes int64
	// Tools maps a tool name to its resolved absolute binary path. Recorded at
	// install time so the runtime does not search PATH on every call; a missing
	// entry falls back to PATH.
	Tools map[string]string
}

// guardEnabled reports whether the execute-time guard is active. The
// pointer defaults to enabled so unset bundles stay protected.
func (r Runner) guardEnabled() bool {
	return r.GuardPrivateIP == nil || *r.GuardPrivateIP
}

const maxToolOutputLineBytes = 1 << 20 // 1 MiB

// DefaultOutputLimit matches config defaults; callers can override it by
// wrapping the sink themselves or via ServerOptions when wired.
const DefaultOutputLimit = 1 << 16

// OutputLimitError is returned by Run when the tool produced more output
// than allowed and was terminated early.
type OutputLimitError struct{ Limit int64 }

func (e *OutputLimitError) Error() string {
	return fmt.Sprintf("output truncated (limit %d bytes)", e.Limit)
}

// Run applies the execute-time private-IP guard to the target and runs
// the job. Keeping the guard inside Run (rather than only wrapping the
// server handler) means ALL callers — the websocket handler and any
// future path — are covered against the DNS-rebinding window between
// token issuance (worker-side check) and execution (agent-side
// re-resolution).
//
// The guard is fail-closed: literal private IPs are rejected, and if the
// target is a hostname that cannot be resolved within the guard timeout
// the job fails with "target resolve failed" instead of falling through.
func (r Runner) Run(ctx context.Context, claims token.JobClaims, w io.Writer) error {
	if r.guardEnabled() {
		host := strings.TrimSpace(claims.Target)
		family := claims.IPVer
		if family == "" {
			family = "ipv4"
		}
		ip, err := guard.ResolveHost(ctx, host, r.ResolveFunc, family)
		if err != nil {
			fmt.Fprintf(w, "job rejected: %v\n", err)
			if errors.Is(err, guard.ErrTargetResolveFailed) {
				return fmt.Errorf("target resolve failed: %w", err)
			}
			return fmt.Errorf("target rejected: %w", err)
		}
		// Execute against the address selected by the guard, never the
		// original hostname (which would trigger a second DNS lookup).
		claims.Target = ip.String()
	}
	return r.RunLimit(ctx, claims, w, r.MaxOutputBytes)
}

// RunLimit runs the job while counting every byte written to w. When the
// total exceeds maxOutputBytes the command is killed (the same way a
// context cancel would terminate it), a final truncation line is emitted
// through the same sink used for normal output, and an OutputLimitError
// is returned.
func (r Runner) RunLimit(ctx context.Context, claims token.JobClaims, w io.Writer, maxOutputBytes int64) error {
	if maxOutputBytes <= 0 {
		maxOutputBytes = DefaultOutputLimit
	}
	if deps.IsBuiltin(claims.Tool) && useBuiltin(r.Tools, claims.Tool) {
		sink := &limitWriter{limit: maxOutputBytes, out: w}
		err := probe.Run(ctx, claims.Tool, claims.Target, claims.IPVer, claims.Count, &builtinLimitWriter{sink: sink})
		if sink.truncated() {
			fmt.Fprintf(w, "output truncated (limit %d bytes)\n", maxOutputBytes)
			return &OutputLimitError{Limit: maxOutputBytes}
		}
		return err
	}
	cmd, err := command(ctx, claims, r.Tools)
	if err != nil {
		return err
	}
	sink := &limitWriter{limit: maxOutputBytes, out: w}
	if claims.Tool == "mtr" {
		return runPTY(cmd, sink)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return err
	}
	scanner := newOutputScanner(stdout)
	for scanner.Scan() {
		if sink.truncated() {
			break
		}
		line := scanner.Text()
		if _, err := fmt.Fprintln(sink, line); err != nil {
			terminate(cmd)
			_ = cmd.Wait()
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		terminate(cmd)
		_ = cmd.Wait()
		return err
	}
	if sink.truncated() {
		terminate(cmd)
		_ = cmd.Wait()
		fmt.Fprintf(w, "output truncated (limit %d bytes)\n", maxOutputBytes)
		return &OutputLimitError{Limit: maxOutputBytes}
	}
	return cmd.Wait()
}

func useBuiltin(tools map[string]string, name string) bool {
	if tools[name] == deps.BuiltinMarker {
		return true
	}
	if !deps.IsAutomaticChoice(tools[name]) {
		return false
	}
	_, err := exec.LookPath(name)
	return err != nil
}

type builtinLimitWriter struct{ sink *limitWriter }

func (w *builtinLimitWriter) Write(p []byte) (int, error) {
	n, err := w.sink.Write(p)
	if w.sink.truncated() {
		return n, &OutputLimitError{Limit: w.sink.limit}
	}
	return n, err
}

func runPTY(cmd *exec.Cmd, w io.Writer) error {
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return err
	}
	defer ptmx.Close()
	scanner := newOutputScanner(ptmx)
	for scanner.Scan() {
		if lw, ok := w.(*limitWriter); ok && lw.truncated() {
			break
		}
		line := strings.TrimRight(scanner.Text(), "\r")
		if _, err := fmt.Fprintln(w, line); err != nil {
			break
		}
	}
	if lw, ok := w.(*limitWriter); ok && lw.truncated() {
		terminate(cmd)
		_ = cmd.Wait()
		fmt.Fprintf(lw.out, "output truncated (limit %d bytes)\n", lw.limit)
		return &OutputLimitError{Limit: lw.limit}
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, syscall.EIO) {
		return err
	}
	return cmd.Wait()
}

// terminate stops the command the same way an expired context does:
// CommandContext kills the process group via ctx, so cancel is enough;
// for explicit truncation we kill the process directly.
func terminate(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

// limitWriter counts total bytes flowing to the output sink and drops
// any bytes beyond limit; callers detect truncation via truncated().
type limitWriter struct {
	limit int64
	out   io.Writer
	n     int64
	// dropped counts bytes that were discarded because the sink was full.
	// Output that fits the limit exactly (n == limit with nothing discarded)
	// is NOT truncation — only actual dropped bytes mark it as such.
	dropped int64
}

func (w *limitWriter) Write(p []byte) (int, error) {
	if w.n >= w.limit {
		w.dropped += int64(len(p))
		return len(p), nil
	}
	remaining := w.limit - w.n
	if int64(len(p)) > remaining {
		n, err := w.out.Write(p[:remaining])
		w.n += int64(n)
		if err != nil {
			return len(p), err
		}
		w.dropped += int64(len(p)) - remaining
		return len(p), nil
	}
	n, err := w.out.Write(p)
	w.n += int64(n)
	return n, err
}

func (w *limitWriter) truncated() bool {
	return w.dropped > 0
}

func newOutputScanner(r io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxToolOutputLineBytes)
	return scanner
}

func command(ctx context.Context, claims token.JobClaims, toolMaps ...map[string]string) (*exec.Cmd, error) {
	if !isIPOrDomain(claims.Target) {
		return nil, fmt.Errorf("invalid target %q", claims.Target)
	}
	var tools map[string]string
	if len(toolMaps) > 0 {
		tools = toolMaps[0]
	}
	bin := func(name string) string {
		if path := deps.UsablePath(tools, name); path != "" {
			return path
		}
		return name
	}
	switch claims.Tool {
	case "ping":
		count := normalizeCount(claims.Count)
		args := []string{"-O", "-c", strconv.Itoa(count), "-W", "2", claims.Target}
		if claims.IPVer == "ipv6" {
			args = append([]string{"-6"}, args...)
		} else {
			args = append([]string{"-4"}, args...)
		}
		return exec.CommandContext(ctx, bin("ping"), args...), nil
	case "mtr":
		// -n disables reverse DNS so each hop is a bare IP with a bounded width
		// (long rDNS names made the streamed table unaligned). The AS number is
		// resolved by the controller after the trace, in one bulk query, so the
		// agent does not need `-z` (which costs per-hop DNS lookups here and is
		// not available in every mtr build).
		args := []string{"--split", "-n", claims.Target}
		if claims.IPVer == "ipv6" {
			args = append([]string{"-6"}, args...)
		} else {
			args = append([]string{"-4"}, args...)
		}
		cmd := exec.CommandContext(ctx, bin("mtr"), args...)
		cmd.Env = append(os.Environ(), "TERM=dumb")
		return cmd, nil
	case "traceroute":
		// -n: no reverse DNS (IPs only, matching the built-in probe).
		// -e: surface ICMP extensions (MPLS labels). -w 2 caps the hop wait.
		args := []string{"-n", "-w", "2", "-e", claims.Target}
		if claims.IPVer == "ipv6" {
			args = append([]string{"-6"}, args...)
		} else {
			args = append([]string{"-4"}, args...)
		}
		return exec.CommandContext(ctx, bin("traceroute"), args...), nil
	case "nexttrace":
		// In NextTrace v1.7.3 --map disables the optional map URL.
		args := []string{"--map", "-g", "en", claims.Target}
		if claims.IPVer == "ipv6" {
			args = append([]string{"--ipv6"}, args...)
		} else {
			args = append([]string{"--ipv4"}, args...)
		}
		return exec.CommandContext(ctx, bin("nexttrace"), args...), nil
	default:
		return nil, fmt.Errorf("unsupported tool %q", claims.Tool)
	}
}

func normalizeCount(count int) int {
	if count == 10 {
		return 10
	}
	return 5
}

func isIPOrDomain(target string) bool {
	target = strings.TrimSpace(target)
	if target == "" || len(target) > 253 || strings.HasPrefix(target, "-") {
		return false
	}
	if ip := net.ParseIP(target); ip != nil {
		return true
	}
	labels := strings.Split(target, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if r > unicode.MaxASCII || (!unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-') {
				return false
			}
		}
	}
	return true
}
