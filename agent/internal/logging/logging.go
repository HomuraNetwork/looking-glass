// Package logging provides leveled logging for the agent.
//
// By default logs go to stdout with timestamps, which is what systemd's
// journal and `logread` consume. Setting a log file redirects output there
// instead (useful for init.d/manual runs that want their own file).
package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"sync"
)

// Level is the minimum severity a logger will emit.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

// ParseLevel maps a config string to a Level. It accepts the usual spellings
// and returns ok=false for anything unrecognized so callers can report it.
func ParseLevel(value string) (Level, bool) {
	switch normalize(value) {
	case "debug":
		return LevelDebug, true
	case "", "info":
		return LevelInfo, true
	case "warn", "warning":
		return LevelWarn, true
	case "error":
		return LevelError, true
	default:
		return LevelInfo, false
	}
}

func normalize(value string) string {
	out := make([]rune, 0, len(value))
	for _, r := range value {
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		if r == ' ' || r == '\t' {
			continue
		}
		out = append(out, r)
	}
	return string(out)
}

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "INFO"
	}
}

// Logger writes timestamped, leveled lines to an optional file and/or stdout.
type Logger struct {
	mu    sync.Mutex
	level Level
	file  *log.Logger
	std   *log.Logger
	// closer is set when Logger owns a file it must close.
	closer io.Closer
}

// Options configures a Logger.
type Options struct {
	// Level is the minimum severity emitted.
	Level Level
	// File, when non-empty, receives the log output (append mode).
	File string
	// Stdout mirrors output to stdout even when File is set. Ignored when
	// File is empty (stdout is always used then).
	Stdout bool
}

// New builds a Logger. When File is empty output goes to stdout.
func New(opts Options) (*Logger, error) {
	l := &Logger{level: opts.Level}
	flags := log.LstdFlags | log.LUTC
	if opts.File == "" {
		l.std = log.New(os.Stdout, "", flags)
		return l, nil
	}
	f, err := os.OpenFile(opts.File, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}
	// O_CREATE does not tighten an existing file's mode, so an older log created
	// as 0640 would stay group-readable even though it can contain tokens and
	// config. Best-effort chmod to owner-only on every open.
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("tighten log file mode: %w", err)
	}
	l.file = log.New(f, "", flags)
	l.closer = f
	if opts.Stdout {
		l.std = log.New(os.Stdout, "", flags)
	}
	return l, nil
}

// Close releases a file opened by New, if any.
func (l *Logger) Close() error {
	if l == nil || l.closer == nil {
		return nil
	}
	err := l.closer.Close()
	l.closer = nil
	return err
}

// Enabled reports whether the given level would be emitted.
func (l *Logger) Enabled(level Level) bool {
	return l != nil && level >= l.level
}

func (l *Logger) emit(level Level, format string, args ...any) {
	if !l.Enabled(level) {
		return
	}
	message := fmt.Sprintf(format, args...)
	line := level.String() + " " + message
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		_ = l.file.Output(2, line)
	}
	if l.std != nil {
		_ = l.std.Output(2, line)
	}
}

func (l *Logger) Debugf(format string, args ...any) { l.emit(LevelDebug, format, args...) }
func (l *Logger) Infof(format string, args ...any)  { l.emit(LevelInfo, format, args...) }
func (l *Logger) Warnf(format string, args ...any)  { l.emit(LevelWarn, format, args...) }
func (l *Logger) Errorf(format string, args ...any) { l.emit(LevelError, format, args...) }

// Fatalf logs at error level and exits with status 1.
func (l *Logger) Fatalf(format string, args ...any) {
	l.emit(LevelError, format, args...)
	os.Exit(1)
}

// defaultLogger is used by the package-level helpers so packages that do not
// receive a Logger (e.g. iperf) still respect the configured level/output.
var (
	defaultMu  sync.RWMutex
	defaultLog = func() *Logger {
		l, _ := New(Options{Level: LevelInfo})
		return l
	}()
)

// SetDefault installs the process-wide logger used by the package helpers.
func SetDefault(l *Logger) {
	if l == nil {
		return
	}
	defaultMu.Lock()
	defaultLog = l
	defaultMu.Unlock()
}

func Default() *Logger {
	defaultMu.RLock()
	defer defaultMu.RUnlock()
	return defaultLog
}

func Debugf(format string, args ...any) { Default().Debugf(format, args...) }
func Infof(format string, args ...any)  { Default().Infof(format, args...) }
func Warnf(format string, args ...any)  { Default().Warnf(format, args...) }
func Errorf(format string, args ...any) { Default().Errorf(format, args...) }

// Fatalf logs through the default logger and exits.
func Fatalf(format string, args ...any) { Default().Fatalf(format, args...) }
