package grants

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type staticUser struct {
	hash  []byte
	rules []rule
}

// minBcryptCost refuses hashes cheap enough to brute-force offline.
const minBcryptCost = 10

func newStaticUser(hash string) (staticUser, error) {
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		return staticUser{}, fmt.Errorf("bcrypt: not a bcrypt hash")
	}
	if cost < minBcryptCost {
		return staticUser{}, fmt.Errorf("bcrypt: cost %d is below %d", cost, minBcryptCost)
	}
	return staticUser{hash: []byte(hash)}, nil
}

// maxPasswordLen is bcrypt's input limit; longer passwords are refused
// rather than silently truncated.
const maxPasswordLen = 72

// StaticAuth checks static users' passwords, caching successes for ttl so
// a burst of pulls doesn't cost one bcrypt each.
type StaticAuth struct {
	ttl   time.Duration
	now   func() time.Time
	mu    sync.Mutex
	cache map[[32]byte]time.Time
}

// NewStaticAuth returns a checker; ttl 0 disables the cache.
func NewStaticAuth(ttl time.Duration) *StaticAuth {
	return &StaticAuth{ttl: ttl, now: time.Now, cache: map[[32]byte]time.Time{}}
}

// maxCacheEntries bounds the success cache.
const maxCacheEntries = 4096

// Check reports whether password is user's password under p.
func (a *StaticAuth) Check(p *Policy, user, password string) bool {
	su, ok := p.staticUsers[user]
	if !ok || len(password) > maxPasswordLen || password == "" {
		return false
	}
	// The key binds the hash too, so a reloaded grants file with a new
	// password invalidates cached successes.
	h := sha256.New()
	for _, part := range [][]byte{[]byte(user), su.hash, []byte(password)} {
		h.Write(part)
		h.Write([]byte{0})
	}
	var key [32]byte
	copy(key[:], h.Sum(nil))

	if a.ttl > 0 {
		a.mu.Lock()
		exp, hit := a.cache[key]
		a.mu.Unlock()
		if hit && a.now().Before(exp) {
			return true
		}
	}
	if bcrypt.CompareHashAndPassword(su.hash, []byte(password)) != nil {
		return false
	}
	if a.ttl > 0 {
		a.mu.Lock()
		if len(a.cache) >= maxCacheEntries {
			now := a.now()
			for k, exp := range a.cache {
				if !now.Before(exp) {
					delete(a.cache, k)
				}
			}
			if len(a.cache) >= maxCacheEntries {
				a.cache = map[[32]byte]time.Time{}
			}
		}
		a.cache[key] = a.now().Add(a.ttl)
		a.mu.Unlock()
	}
	return true
}
