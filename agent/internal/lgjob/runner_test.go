package lgjob

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"hlg/internal/token"
)

func TestCommandRejectsInvalidTargets(t *testing.T) {
	_, err := command(context.Background(), token.JobClaims{
		Tool:   "ping",
		Target: "-c",
		IPVer:  "ipv4",
		Count:  4,
	})
	if err == nil {
		t.Fatal("expected invalid target to fail")
	}
}

func TestUseBuiltinAutomaticWhenUnset(t *testing.T) {
	// An unset (or empty) choice means automatic: the built-in is used when no
	// system binary exists.
	t.Setenv("PATH", t.TempDir())
	if !useBuiltin(map[string]string{}, "mtr") {
		t.Fatal("unset choice with no system binary should use the built-in probe")
	}
	if !useBuiltin(map[string]string{"mtr": ""}, "mtr") {
		t.Fatal("empty choice should use the built-in probe")
	}
}

func TestRunUsesValidatedResolvedIPInsteadOfHostname(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	script := filepath.Join(dir, "ping")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > "+argsFile+"\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	var out bytes.Buffer
	runner := Runner{ResolveFunc: func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("192.0.2.4")}, nil
	}}
	if err := runner.Run(context.Background(), token.JobClaims{Tool: "ping", Target: "host.example", IPVer: "ipv4", Count: 5}, &out); err != nil {
		t.Fatal(err)
	}
	args, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(args), "host.example") || !strings.Contains(string(args), "192.0.2.4") {
		t.Fatalf("tool received unexpected target args: %q", args)
	}
}

func TestPingCommandUsesAllowedCountWithPerPacketTimeout(t *testing.T) {
	cmd, err := command(context.Background(), token.JobClaims{
		Tool:   "ping",
		Target: "example.com",
		IPVer:  "ipv4",
		Count:  10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(cmd.Path) != "ping" {
		t.Fatalf("command path = %q, want ping", cmd.Path)
	}
	args := strings.Join(cmd.Args[1:], " ")
	if args != "-4 -O -c 10 -W 2 example.com" {
		t.Fatalf("args = %q", args)
	}
	if strings.Contains(args, "-w") {
		t.Fatalf("ping args should not use deadline mode that can exceed count: %q", args)
	}
}

func TestPingCommandDefaultsUnsupportedCountToFive(t *testing.T) {
	cmd, err := command(context.Background(), token.JobClaims{
		Tool:   "ping",
		Target: "example.com",
		IPVer:  "ipv4",
		Count:  7,
	})
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Join(cmd.Args[1:], " ")
	if args != "-4 -O -c 5 -W 2 example.com" {
		t.Fatalf("args = %q", args)
	}
}

func TestMTRCommandUsesSplitStreamingWithoutCurses(t *testing.T) {
	cmd, err := command(context.Background(), token.JobClaims{
		Tool:   "mtr",
		Target: "example.com",
		IPVer:  "ipv6",
		Count:  10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(cmd.Path) != "mtr" {
		t.Fatalf("path = %q", cmd.Path)
	}
	args := strings.Join(cmd.Args[1:], " ")
	if args != "-6 --split -n example.com" {
		t.Fatalf("args = %q", args)
	}
	if strings.Contains(args, "-c") {
		t.Fatalf("mtr args should be live streaming without count mode: %q", args)
	}
	if !contains(cmd.Env, "TERM=dumb") {
		t.Fatalf("TERM=dumb missing from env: %#v", cmd.Env)
	}
	if strings.Contains(args, "--raw") || strings.Contains(args, "--curses") {
		t.Fatalf("mtr args must not use curses: %q", args)
	}
}

func TestNexttraceCommandBuildsWithoutNoColorFlag(t *testing.T) {
	cmd, err := command(context.Background(), token.JobClaims{
		Tool:   "nexttrace",
		Target: "example.com",
		IPVer:  "ipv4",
	})
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(cmd.Path) != "nexttrace" {
		t.Fatalf("path = %q", cmd.Path)
	}
	args := strings.Join(cmd.Args[1:], " ")
	if strings.Contains(args, "-C") || strings.Contains(args, "--no-color") {
		t.Fatalf("nexttrace must not contain -C or --no-color flag: %q", args)
	}
	if !strings.Contains(args, "--ipv4") || !strings.Contains(args, "--map") || !strings.Contains(args, "-g en") {
		t.Fatalf("expected IPv4, no-map and English args, got: %q", args)
	}
}

func TestBuiltinSelection(t *testing.T) {
	if !useBuiltin(map[string]string{"ping": "builtin"}, "ping") {
		t.Fatal("explicit built-in choice ignored")
	}
	if useBuiltin(map[string]string{"ping": "/usr/bin/ping"}, "ping") {
		t.Fatal("explicit system path ignored")
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestRunLimitTruncatesExcessiveOutput(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh unavailable")
	}
	if _, err := exec.LookPath("yes"); err != nil {
		t.Skip("yes unavailable")
	}
	var out bytes.Buffer
	cmd := exec.Command("yes", "0123456789")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()
	sink := &limitWriter{limit: 512, out: &out}
	scanner := newOutputScanner(stdout)
	for scanner.Scan() {
		if sink.truncated() {
			break
		}
		if _, err := fmt.Fprintln(sink, scanner.Text()); err != nil {
			break
		}
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	if out.Len() < 512 {
		t.Fatalf("sink length = %d, want at least 512 truncated bytes", out.Len())
	}
	if out.Len() > 512+len("yes line\n") {
		t.Fatalf("sink length = %d, limit not enforced", out.Len())
	}
}

func TestRunLimitTerminatesPingBeyondOutputCap(t *testing.T) {
	if _, err := exec.LookPath("ping"); err != nil {
		t.Skip("ping unavailable")
	}
	var out bytes.Buffer
	err := Runner{}.RunLimit(context.Background(), token.JobClaims{
		Tool:   "ping",
		Target: "127.0.0.1",
		IPVer:  "ipv4",
		Count:  10,
	}, &out, 32)
	var limitErr *OutputLimitError
	if !errors.As(err, &limitErr) {
		t.Fatalf("expected OutputLimitError, got %v", err)
	}
	if limitErr.Limit != 32 {
		t.Fatalf("limit = %d, want 32", limitErr.Limit)
	}
	if !strings.Contains(out.String(), "output truncated (limit 32 bytes)") {
		t.Fatalf("truncation notice missing from output: %q", out.String())
	}
	if out.Len() > 32+len("output truncated (limit 32 bytes)\n") {
		t.Fatalf("sink exceeded limit+notice: %d bytes", out.Len())
	}
}

func TestLimitWriterBoundaryBehavior(t *testing.T) {
	cases := []struct {
		name          string
		writes        [][]byte
		wantReturn    []int
		wantOutput    string
		wantTruncated bool
	}{
		{name: "exact fit", writes: [][]byte{[]byte("12345678")}, wantReturn: []int{8}, wantOutput: "12345678"},
		{name: "later write overflows", writes: [][]byte{[]byte("12345678"), []byte("abcd")}, wantReturn: []int{8, 4}, wantOutput: "12345678", wantTruncated: true},
		{name: "single write straddles limit", writes: [][]byte{[]byte("12345678X")}, wantReturn: []int{9}, wantOutput: "12345678", wantTruncated: true},
	}
	for _, tc := range cases {
		var out bytes.Buffer
		sink := &limitWriter{limit: 8, out: &out}
		for i, input := range tc.writes {
			n, err := sink.Write(input)
			if err != nil || n != tc.wantReturn[i] {
				t.Errorf("%s: write = %d, %v; want %d, nil", tc.name, n, err, tc.wantReturn[i])
			}
		}
		if out.String() != tc.wantOutput {
			t.Errorf("%s: output = %q, want %q", tc.name, out.String(), tc.wantOutput)
		}
		if sink.truncated() != tc.wantTruncated {
			t.Errorf("%s: truncated = %t, want %t", tc.name, sink.truncated(), tc.wantTruncated)
		}
	}
}
