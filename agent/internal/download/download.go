package download

import (
	"crypto/rand"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const maxInt64 = int64(^uint64(0) >> 1)

func SizeBytes(size string) (int64, error) {
	size = strings.TrimSpace(strings.ToUpper(size))
	switch {
	case strings.HasSuffix(size, "M"):
		value, err := strconv.ParseInt(strings.TrimSuffix(size, "M"), 10, 64)
		if err != nil {
			return 0, err
		}
		return bytesForUnit(size, value, 1024*1024)
	case strings.HasSuffix(size, "G"):
		value, err := strconv.ParseInt(strings.TrimSuffix(size, "G"), 10, 64)
		if err != nil {
			return 0, err
		}
		return bytesForUnit(size, value, 1024*1024*1024)
	default:
		return 0, fmt.Errorf("unsupported size %q", size)
	}
}

func bytesForUnit(size string, value int64, unit int64) (int64, error) {
	if value <= 0 {
		return 0, fmt.Errorf("unsupported size %q", size)
	}
	if value > maxInt64/unit {
		return 0, fmt.Errorf("size overflow %q", size)
	}
	return value * unit, nil
}

func WriteVirtual(w io.Writer, bytes int64) error {
	_, err := io.CopyN(w, rand.Reader, bytes)
	return err
}
