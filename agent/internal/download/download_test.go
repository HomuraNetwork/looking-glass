package download

import (
	"bytes"
	"compress/gzip"
	"testing"
	"time"
)

func TestSizeBytesRejectsOverflowAndNonPositiveValues(t *testing.T) {
	for _, size := range []string{"0M", "-1M", "9223372036854775807G"} {
		if _, err := SizeBytes(size); err == nil {
			t.Fatalf("SizeBytes(%q) expected error", size)
		}
	}
}

func TestWriteVirtualUsesUncompressiblePerRequestData(t *testing.T) {
	first := bytes.NewBuffer(nil)
	second := bytes.NewBuffer(nil)
	if err := WriteVirtual(first, 64*1024); err != nil {
		t.Fatal(err)
	}
	if err := WriteVirtual(second, 64*1024); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("download bodies must not repeat the same cacheable pattern")
	}
	if compressedSize(first.Bytes()) < first.Len()/2 {
		t.Fatalf("download body compressed too well: raw=%d gzip=%d", first.Len(), compressedSize(first.Bytes()))
	}
}

func budgetForTest(maxRequests int, multiplier int64, window time.Duration) *Budget {
	return NewBudget(BudgetLimits{
		Window:              window,
		MaxRequestsPerToken: maxRequests,
		MaxBytesMultiplier:  multiplier,
	})
}

func TestBudgetAllowsRetriesThenRejectsBeyondMultiplier(t *testing.T) {
	budget := budgetForTest(12, 4, 15*time.Minute)
	now := time.Now()

	// First request seeds the budget: requestBytes * multiplier.
	if !budget.Allow("token-a", 1000, now) {
		t.Fatal("first request should be allowed")
	}
	for i := 0; i < 3; i++ {
		if !budget.Allow("token-a", 1000, now) {
			t.Fatalf("retry %d should be allowed within multiplier budget", i)
		}
	}
	if budget.Allow("token-a", 1000, now) {
		t.Fatal("5th request of 4x budget should be rejected")
	}
	if budget.Allow("token-a", 500, now) {
		t.Fatal("smaller request should still be rejected once budget is exhausted")
	}
}

func TestBudgetAllowsFewRequestsButRejectsTooMany(t *testing.T) {
	budget := budgetForTest(4, 4, 15*time.Minute)
	now := time.Now()
	for i := 0; i < 4; i++ {
		if !budget.Allow("token-b", 10, now) {
			t.Fatalf("request %d should be allowed", i)
		}
	}
	if budget.Allow("token-b", 10, now) {
		t.Fatal("5th request should be rejected by request cap")
	}
}

func TestBudgetTracksTokensIndependently(t *testing.T) {
	budget := budgetForTest(12, 4, 15*time.Minute)
	now := time.Now()
	if !budget.Allow("token-c", 1000, now) {
		t.Fatal("token-c first request should be allowed")
	}
	for i := 0; i < 3; i++ {
		if !budget.Allow("token-c", 1000, now) {
			t.Fatalf("token-c retry %d should be allowed", i)
		}
	}
	if budget.Allow("token-c", 1000, now) {
		t.Fatal("token-c should be rejected at request cap")
	}
	if !budget.Allow("token-d", 1000, now) {
		t.Fatal("independent token-d should be unaffected by token-c exhaustion")
	}
}

func TestBudgetWindowResetAllowsFreshRequests(t *testing.T) {
	budget := budgetForTest(2, 4, 15*time.Minute)
	start := time.Now()
	if !budget.Allow("token-e", 1000, start) || !budget.Allow("token-e", 1000, start) {
		t.Fatal("initial requests should be allowed")
	}
	if budget.Allow("token-e", 1000, start) {
		t.Fatal("request cap should be enforced inside the window")
	}
	if !budget.Allow("token-e", 1000, start.Add(15*time.Minute)) {
		t.Fatal("requests after the window should start fresh")
	}
}

func TestBudgetEvictionKeepsMemoryBounded(t *testing.T) {
	budget := budgetForTest(2, 2, time.Minute)
	base := time.Now()
	for i := 0; i < 10000; i++ {
		token := make([]byte, 0, 8)
		token = append(token, "tok-0000"...)
		token[4] = byte('0' + (i/1000)%10)
		token[5] = byte('0' + (i/100)%10)
		token[6] = byte('0' + (i/10)%10)
		token[7] = byte('0' + i%10)
		budget.Allow(string(token), 1, base.Add(time.Duration(i)*time.Millisecond))
	}
	if budget.Len() > 4096 {
		t.Fatalf("budget cache grew unbounded: %d entries", budget.Len())
	}
}

func TestZeroLimitsDoNotPanic(t *testing.T) {
	budget := NewBudget(BudgetLimits{})
	if !budget.Allow("token-f", 100, time.Now()) {
		t.Fatal("unlimited budget should always allow")
	}
}

func compressedSize(data []byte) int {
	out := bytes.NewBuffer(nil)
	writer := gzip.NewWriter(out)
	_, _ = writer.Write(data)
	_ = writer.Close()
	return out.Len()
}
