package download

import (
	"crypto/sha256"
	"sync"
	"time"
)

// BudgetLimits bounds how much a single download token may be replayed.
// Window is the rolling window counted from the token's first use; max
// requests and cumulative bytes are enforced per token within it.
type BudgetLimits struct {
	Window              time.Duration
	MaxRequestsPerToken int
	MaxBytesMultiplier  int64
}

type budgetEntry struct {
	usedBytes   int64
	requests    int
	windowStart time.Time
	lastUsed    time.Time
}

// Budget tracks per-token download usage keyed by the SHA-256 of the raw
// token string. Entries are capped so memory stays bounded; the least
// recently used entry is evicted once the cache is full.
type Budget struct {
	mu      sync.Mutex
	limits  BudgetLimits
	entries map[[sha256.Size]byte]*budgetEntry
	maxSize int
}

const maxBudgetEntries = 4096

func NewBudget(limits BudgetLimits) *Budget {
	return &Budget{
		limits:  limits,
		entries: make(map[[sha256.Size]byte]*budgetEntry),
		maxSize: maxBudgetEntries,
	}
}

// Allow records one request for rawToken serving requestBytes. It returns
// false when the token has exhausted its request or byte budget for the
// current window; rejected requests must not generate bytes.
func (b *Budget) Allow(rawToken string, requestBytes int64, now time.Time) bool {
	if b == nil || rawToken == "" {
		return false
	}
	key := sha256.Sum256([]byte(rawToken))
	b.mu.Lock()
	defer b.mu.Unlock()
	entry, ok := b.entries[key]
	if ok && b.limits.Window > 0 && now.Sub(entry.windowStart) >= b.limits.Window {
		ok = false
	}
	if !ok {
		entry = &budgetEntry{windowStart: now}
		b.entries[key] = entry
	}
	entry.lastUsed = now
	if b.limits.MaxRequestsPerToken > 0 && entry.requests >= b.limits.MaxRequestsPerToken {
		return false
	}
	if b.limits.MaxBytesMultiplier > 0 && entry.usedBytes > 0 && entry.usedBytes+requestBytes > requestBytes*b.limits.MaxBytesMultiplier {
		return false
	}
	entry.requests++
	entry.usedBytes += requestBytes
	b.evictLocked(now)
	return true
}

// Len reports how many tokens are currently tracked; used by tests.
func (b *Budget) Len() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.entries)
}

func (b *Budget) evictLocked(now time.Time) {
	for len(b.entries) > b.maxSize {
		var oldestKey [sha256.Size]byte
		var oldest time.Time
		for key, entry := range b.entries {
			if oldest.IsZero() || entry.lastUsed.Before(oldest) {
				oldest = entry.lastUsed
				oldestKey = key
			}
		}
		delete(b.entries, oldestKey)
	}
}
