package server

import (
	crand "crypto/rand"
	"encoding/hex"
	"strconv"
	"sync"
	"time"
)

// semaphore is a tiny channel-based counting semaphore (golang.org/x/sync
// is not vendored). Slots are pre-filled so tryAcquire can poll without a
// separate counter.
type semaphore struct {
	slots chan struct{}
}

func newSemaphore(n int) *semaphore {
	if n <= 0 {
		n = 1
	}
	s := &semaphore{slots: make(chan struct{}, n)}
	for i := 0; i < n; i++ {
		s.slots <- struct{}{}
	}
	return s
}

// tryAcquire takes a slot without blocking; it reports false when the
// semaphore is saturated.
func (s *semaphore) tryAcquire() bool {
	select {
	case <-s.slots:
		return true
	default:
		return false
	}
}

func (s *semaphore) release() {
	s.slots <- struct{}{}
}

func (s *semaphore) size() int {
	return cap(s.slots)
}

// ipJobLimiter bounds the number of concurrent jobs per client IP.
type ipJobLimiter struct {
	mu     sync.Mutex
	limit  int
	active map[string]int
}

func newIPJobLimiter(limit int) *ipJobLimiter {
	if limit <= 0 {
		limit = 1
	}
	return &ipJobLimiter{limit: limit, active: make(map[string]int)}
}

// acquire registers a running job for ip. It returns ok=false when the IP
// is already at its concurrency limit; otherwise the returned release func
// must be called (via defer, so it also runs on timeout/panic) when the
// job finishes.
func (l *ipJobLimiter) acquire(ip string) (release func(), ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active[ip] >= l.limit {
		return nil, false
	}
	l.active[ip]++
	return func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.active[ip] > 0 {
			l.active[ip]--
		}
		if l.active[ip] == 0 {
			delete(l.active, ip)
		}
	}, true
}

// acquireKeyed registers a running job under key. When key is empty the job
// is counted under a distinct synthetic key, so it is never serialized with
// other callers: proxied jobs arrive from the worker's egress IP, and
// bucketing them all by that shared peer address would collapse every
// browser user into a single concurrency slot (with the default limit of 1,
// the whole node would run one proxied job at a time). The per-IP limit still
// applies to direct visitors, whose TCP peer is their own address.
func (l *ipJobLimiter) acquireKeyed(key string) (release func(), ok bool) {
	if key == "" {
		var buf [8]byte
		if _, err := crand.Read(buf[:]); err != nil {
			// crypto/rand never fails on supported platforms; fall back to a
			// time-based key rather than serializing unrelated jobs.
			key = "anon:" + strconv.FormatInt(time.Now().UnixNano(), 36)
			return l.acquire(key)
		}
		key = "anon:" + hex.EncodeToString(buf[:])
	}
	return l.acquire(key)
}
