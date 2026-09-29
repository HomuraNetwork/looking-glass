package keyset

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"

	"hlg/internal/config"
)

var (
	ErrUnknownKID = errors.New("unknown kid")
	ErrWrongUse   = errors.New("wrong key use")
	ErrBadKey     = errors.New("bad key")
)

type Keyset struct {
	mu   sync.RWMutex
	keys map[string]entry
}

type entry struct {
	use string
	key ed25519.PublicKey
}

func New(keys []config.Key) (*Keyset, error) {
	ks := &Keyset{keys: make(map[string]entry, len(keys))}
	if err := ks.Add(keys); err != nil {
		return nil, err
	}
	return ks, nil
}

func (ks *Keyset) Add(keys []config.Key) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	for _, item := range keys {
		if item.Alg != "Ed25519" {
			return fmt.Errorf("%w: unsupported alg %q", ErrBadKey, item.Alg)
		}
		raw, err := base64.RawURLEncoding.DecodeString(item.PublicKey)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrBadKey, item.KID)
		}
		if len(raw) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: %s", ErrBadKey, item.KID)
		}
		ks.keys[item.KID] = entry{use: item.Use, key: ed25519.PublicKey(raw)}
	}
	return nil
}

func (ks *Keyset) PublicKey(kid, use string) (ed25519.PublicKey, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	found, ok := ks.keys[kid]
	if !ok {
		return nil, ErrUnknownKID
	}
	if found.use != use {
		return nil, ErrWrongUse
	}
	return append(ed25519.PublicKey(nil), found.key...), nil
}
