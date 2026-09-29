package token

import (
	"container/list"
	"sync"
	"time"
)

type NonceCache struct {
	mu      sync.Mutex
	max     int
	ttl     time.Duration
	entries map[string]*list.Element
	order   *list.List
}

type nonceEntry struct {
	nonce     string
	expiresAt time.Time
}

// Cache sizing: the TTL must cover the longest window in which a captured
// request could still be replayed (the 300s job-token window plus margin),
// and the capacity must comfortably exceed the worst-case request flood
// within one TTL so a flood cannot LRU-evict a still-live nonce and let the
// same nonce be replayed.
const (
	DefaultNonceCacheCapacity = 50000
	DefaultNonceCacheTTL      = 11 * time.Minute
)

func NewNonceCache(max int, ttl time.Duration) *NonceCache {
	if max <= 0 {
		max = DefaultNonceCacheCapacity
	}
	if ttl <= 0 {
		ttl = DefaultNonceCacheTTL
	}
	return &NonceCache{
		max:     max,
		ttl:     ttl,
		entries: make(map[string]*list.Element, max),
		order:   list.New(),
	}
}

func (c *NonceCache) Use(nonce string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.prune(now)
	if _, ok := c.entries[nonce]; ok {
		return false
	}
	elem := c.order.PushBack(nonceEntry{nonce: nonce, expiresAt: now.Add(c.ttl)})
	c.entries[nonce] = elem
	// Evict expired entries anywhere in the list before resorting to LRU, so
	// a flood cannot push a still-live nonce out of the cache (which would
	// allow the same nonce to be replayed).
	for len(c.entries) > c.max {
		if c.removeExpiredLocked(now) {
			continue
		}
		front := c.order.Front()
		if front == nil {
			break
		}
		c.order.Remove(front)
		delete(c.entries, front.Value.(nonceEntry).nonce)
	}
	return true
}

// removeExpiredLocked evicts the next expired entry anywhere in the list.
// Returns false when no expired entry remains.
func (c *NonceCache) removeExpiredLocked(now time.Time) bool {
	for elem := c.order.Front(); elem != nil; elem = elem.Next() {
		entry := elem.Value.(nonceEntry)
		if entry.expiresAt.After(now) {
			continue
		}
		c.order.Remove(elem)
		delete(c.entries, entry.nonce)
		return true
	}
	return false
}

func (c *NonceCache) prune(now time.Time) {
	for elem := c.order.Front(); elem != nil; {
		next := elem.Next()
		entry := elem.Value.(nonceEntry)
		if entry.expiresAt.After(now) {
			break
		}
		c.order.Remove(elem)
		delete(c.entries, entry.nonce)
		elem = next
	}
}
