package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	cases := map[string]struct {
		level Level
		ok    bool
	}{
		"debug":   {LevelDebug, true},
		"DEBUG":   {LevelDebug, true},
		"":        {LevelInfo, true},
		"info":    {LevelInfo, true},
		" Info ":  {LevelInfo, true},
		"warn":    {LevelWarn, true},
		"warning": {LevelWarn, true},
		"error":   {LevelError, true},
		"bogus":   {LevelInfo, false},
	}
	for input, want := range cases {
		got, ok := ParseLevel(input)
		if got != want.level || ok != want.ok {
			t.Fatalf("ParseLevel(%q) = (%v, %v), want (%v, %v)", input, got, ok, want.level, want.ok)
		}
	}
}

func TestLevelFiltersOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.log")
	logger, err := New(Options{Level: LevelWarn, File: path})
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()

	logger.Debugf("debug line")
	logger.Infof("info line")
	logger.Warnf("warn line %d", 42)
	logger.Errorf("error line")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	if strings.Contains(out, "debug line") || strings.Contains(out, "info line") {
		t.Fatalf("below-threshold lines leaked: %q", out)
	}
	if !strings.Contains(out, "WARN warn line 42") || !strings.Contains(out, "ERROR error line") {
		t.Fatalf("leveled lines missing: %q", out)
	}
}

func TestFileOutputAppendsAndCloses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.log")
	first, err := New(Options{Level: LevelInfo, File: path})
	if err != nil {
		t.Fatal(err)
	}
	first.Infof("first run")
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := New(Options{Level: LevelInfo, File: path})
	if err != nil {
		t.Fatal(err)
	}
	second.Infof("second run")
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "first run") || !strings.Contains(string(data), "second run") {
		t.Fatalf("expected append across runs, got %q", string(data))
	}
}

func TestNewRejectsUnwritableLogFile(t *testing.T) {
	// A directory path cannot be opened as a file.
	if _, err := New(Options{Level: LevelInfo, File: t.TempDir()}); err == nil {
		t.Fatal("expected error for unwritable log file")
	}
}

func TestDefaultLoggerRespectsLevel(t *testing.T) {
	restore := Default()
	defer SetDefault(restore)

	path := filepath.Join(t.TempDir(), "default.log")
	logger, err := New(Options{Level: LevelError, File: path})
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	SetDefault(logger)

	Infof("should be filtered")
	Errorf("should appear")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "should be filtered") {
		t.Fatalf("default logger ignored level: %q", string(data))
	}
	if !strings.Contains(string(data), "should appear") {
		t.Fatalf("default logger dropped an error: %q", string(data))
	}
}
