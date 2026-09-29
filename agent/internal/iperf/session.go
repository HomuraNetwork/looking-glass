package iperf

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

func confirmListen(ctx context.Context, port int) error {
	deadline := time.Now().Add(2 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		listening, err := procNetHasListenPort(port)
		if listening {
			return nil
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("port %d is not listening", port)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return fmt.Errorf("iperf3 listener was not ready on port %d: %w", port, lastErr)
}

func procNetHasListenPort(port int) (bool, error) {
	var joined error
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		listening, err := procNetFileHasListenPort(path, port)
		if listening {
			return true, nil
		}
		if err != nil {
			joined = errors.Join(joined, err)
		}
	}
	return false, joined
}

func procNetFileHasListenPort(path string, port int) (bool, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	wantPort := fmt.Sprintf("%04X", port)
	for _, line := range strings.Split(string(content), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		_, portHex, ok := strings.Cut(fields[1], ":")
		if ok && strings.EqualFold(portHex, wantPort) && fields[3] == "0A" {
			return true, nil
		}
	}
	return false, nil
}
