// Package licenses exposes the notices generated for the distributed Agent.
package licenses

import "fmt"

//go:generate go run ../../tools/generate-licenses.go

// Set by notices_generated.go. Development builds can compile without that
// file; release builds run go generate before compiling.
var text string

func Text() (string, error) {
	if text == "" {
		return "", fmt.Errorf("license notices were not generated; run go generate ./internal/licenses from agent/ and rebuild")
	}
	return text, nil
}
