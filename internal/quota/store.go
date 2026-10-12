package quota

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
	bolterrors "go.etcd.io/bbolt/errors"
)

var (
	bucketRepos     = []byte("repos")     // repository → {digest: size} it reaches
	bucketManifests = []byte("manifests") // digest → manifestInfo (immutable)
	bucketBlobs     = []byte("blobs")     // digest → size (immutable)
	bucketMeta      = []byte("meta")
	keyRebuilt      = []byte("rebuilt") // unix time of the last complete rebuild
)

// ErrLocked means another process (a running server) holds the store.
var ErrLocked = errors.New("the quota store is in use by another process")

// Usage is one namespace's storage.
type Usage struct {
	Used  int64 // bytes of distinct blobs
	Blobs int   // distinct blobs, manifests included
}

// Store keeps, per repository, the blobs its tags reach, and the
// per-namespace totals in memory.
type Store struct {
	db *bolt.DB

	mu      sync.RWMutex
	repos   map[string]map[string]int64
	byNS    map[string]map[string]bool // namespace → repositories
	usage   map[string]Usage
	rebuilt time.Time
}

// Namespace is a repository's top-level path component.
func Namespace(repo string) string {
	ns, _, _ := strings.Cut(repo, "/")
	return ns
}

// Open opens or creates the store at path. A store that never completed a
// rebuild (new, or lost) reports a zero Rebuilt time.
func Open(path string, lockWait time.Duration) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: lockWait})
	if errors.Is(err, bolterrors.ErrTimeout) {
		return nil, ErrLocked
	}
	if err != nil {
		return nil, fmt.Errorf("quota store %s: %w", path, err)
	}
	s := &Store{db: db, repos: map[string]map[string]int64{}, byNS: map[string]map[string]bool{}, usage: map[string]Usage{}}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketRepos, bucketManifests, bucketBlobs, bucketMeta} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		if v := tx.Bucket(bucketMeta).Get(keyRebuilt); len(v) == 8 {
			s.rebuilt = time.Unix(int64(binary.BigEndian.Uint64(v)), 0)
		}
		return tx.Bucket(bucketRepos).ForEach(func(k, v []byte) error {
			var blobs map[string]int64
			if err := json.Unmarshal(v, &blobs); err != nil {
				return fmt.Errorf("repository %s: %w", k, err)
			}
			s.setLocked(string(k), blobs)
			return nil
		})
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("quota store %s: %w", path, err)
	}
	for ns := range s.byNS {
		s.recount(ns)
	}
	return s, nil
}

// Close closes the store.
func (s *Store) Close() error { return s.db.Close() }

// Rebuilt is when the last complete rebuild finished; zero if never.
func (s *Store) Rebuilt() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rebuilt
}

func (s *Store) setLocked(repo string, blobs map[string]int64) {
	ns := Namespace(repo)
	if len(blobs) == 0 {
		delete(s.repos, repo)
		delete(s.byNS[ns], repo)
		if len(s.byNS[ns]) == 0 {
			delete(s.byNS, ns)
		}
		return
	}
	s.repos[repo] = blobs
	if s.byNS[ns] == nil {
		s.byNS[ns] = map[string]bool{}
	}
	s.byNS[ns][repo] = true
}

// recount totals a namespace's distinct blobs. Callers hold s.mu.
func (s *Store) recount(ns string) {
	seen := map[string]int64{}
	for repo := range s.byNS[ns] {
		for d, size := range s.repos[repo] {
			seen[d] = size
		}
	}
	if len(seen) == 0 {
		delete(s.usage, ns)
		return
	}
	u := Usage{Blobs: len(seen)}
	for _, size := range seen {
		u.Used += size
	}
	s.usage[ns] = u
}

// SetRepo records the blobs a repository reaches; none removes it.
func (s *Store) SetRepo(repo string, blobs map[string]int64) error {
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketRepos)
		if len(blobs) == 0 {
			return b.Delete([]byte(repo))
		}
		data, err := json.Marshal(blobs)
		if err != nil {
			return err
		}
		return b.Put([]byte(repo), data)
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setLocked(repo, blobs)
	s.recount(Namespace(repo))
	return nil
}

// Repos lists the repositories with stored content.
func (s *Store) Repos() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.repos))
	for r := range s.repos {
		out = append(out, r)
	}
	return out
}

// Usage returns a namespace's usage.
func (s *Store) Usage(ns string) Usage {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.usage[ns]
}

// All returns every namespace's usage.
func (s *Store) All() map[string]Usage {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]Usage, len(s.usage))
	for ns, u := range s.usage {
		out[ns] = u
	}
	return out
}

func (s *Store) manifest(digest string) (manifestInfo, bool) {
	var info manifestInfo
	var ok bool
	_ = s.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(bucketManifests).Get([]byte(digest)); v != nil {
			ok = json.Unmarshal(v, &info) == nil
		}
		return nil
	})
	return info, ok
}

func (s *Store) putManifest(digest string, info manifestInfo) error {
	data, err := json.Marshal(info)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucketManifests).Put([]byte(digest), data) })
}

func (s *Store) blobSize(digest string) (int64, bool) {
	var size int64
	var ok bool
	_ = s.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(bucketBlobs).Get([]byte(digest)); len(v) == 8 {
			size, ok = int64(binary.BigEndian.Uint64(v)), true
		}
		return nil
	})
	return size, ok
}

func (s *Store) putBlobSize(digest string, size int64) error {
	v := binary.BigEndian.AppendUint64(nil, uint64(size))
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucketBlobs).Put([]byte(digest), v) })
}

// finishRebuild drops the repositories not in keep, prunes the caches to
// what some repository still reaches, and records the rebuild time.
func (s *Store) finishRebuild(keep map[string]bool, at time.Time) error {
	for _, repo := range s.Repos() {
		if !keep[repo] {
			if err := s.SetRepo(repo, nil); err != nil {
				return err
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	live := map[string]bool{}
	for _, blobs := range s.repos {
		for d := range blobs {
			live[d] = true
		}
	}
	err := s.db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{bucketManifests, bucketBlobs} {
			b := tx.Bucket(name)
			var stale [][]byte
			_ = b.ForEach(func(k, _ []byte) error {
				if !live[string(k)] {
					stale = append(stale, append([]byte(nil), k...))
				}
				return nil
			})
			for _, k := range stale {
				if err := b.Delete(k); err != nil {
					return err
				}
			}
		}
		return tx.Bucket(bucketMeta).Put(keyRebuilt, binary.BigEndian.AppendUint64(nil, uint64(at.Unix())))
	})
	if err != nil {
		return err
	}
	s.rebuilt = at
	return nil
}
