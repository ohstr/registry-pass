// Package membership keeps the view of who is a member, built only from
// events signed by the configured authorities.
package membership

import (
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip09"
	"github.com/ohstr/nmilat/nip19"
)

// Options configures a Store; it mirrors config.Membership.
type Options struct {
	Authorities     []string // lowercase hex
	Kind            int
	DPrefix         string
	NameMismatch    string // reject | useD
	Resolve         string // latest | deadWins
	FutureSkew      time.Duration
	HonorDeletions  bool
	DuplicatePubkey string // denyAll | newestWins
	StaleAfter      time.Duration
	OnStale         string // denyMembers | denyAll | keepLastView
	Heartbeat       bool
	HeartbeatD      string
	Now             func() time.Time
}

// Rejection classifies an event the store refused; it labels metrics.
type Rejection string

const (
	RejectBadSignature Rejection = "bad_signature"
	RejectNotAuthority Rejection = "not_authority"
	RejectWrongKind    Rejection = "wrong_kind"
	RejectFuture       Rejection = "future_dated"
	RejectOtherD       Rejection = "other_d"
	RejectStale        Rejection = "older_than_current"
	RejectDeleted      Rejection = "deleted"
)

// Status values of a membership record.
const (
	StatusAlive   = "alive"
	StatusDead    = "dead"
	statusInvalid = "invalid" // authority-signed but unreadable: grants nothing
)

// Record is one authority's current version of one member slot.
type Record struct {
	Authority string
	D         string
	Name      string
	Pubkey    string
	Status    string
	CreatedAt uint64
	ID        string
	event     *nip01.Event
}

// Member is an alive member resolved from the records.
type Member struct {
	Name   string
	Pubkey string
	Since  time.Time
}

// Snapshot is an immutable view of the membership.
type Snapshot struct {
	byPubkey  map[string]Member
	conflicts map[string]bool
	Size      int
	Records   int
	Conflicts int
}

// Lookup is the answer for one pubkey.
type Lookup struct {
	// Name is the member's name, empty when the pubkey gets no template
	// grants (not a member, dead, conflicting, or membership stale under
	// denyMembers).
	Name string
	// Stale reports that the membership view is not fresh.
	Stale bool
	// DenyAll is set when stale and onStale is denyAll: refuse every token
	// that depends on a Nostr identity.
	DenyAll bool
	// Conflict reports a pubkey claimed by two alive records.
	Conflict bool
}

// Freshness reports whether a source's data is current.
type Freshness interface {
	// LastSync is when the source last completed a full, trustworthy read;
	// zero if never.
	LastSync() time.Time
}

type slotKey struct{ authority, d string }

// Store holds verified records and resolves them into a Snapshot.
type Store struct {
	opts        Options
	authorities map[string]bool

	mu        sync.Mutex
	records   map[slotKey]*Record
	deletedTo map[slotKey]uint64 // NIP-09: (author,d) deleted up to created_at
	deletedID map[string]bool
	heartbeat uint64
	dirty     bool
	sources   []Freshness

	snap atomic.Pointer[Snapshot]

	stats sync.Map // Rejection -> *atomic.Int64
}

// New returns an empty store.
func New(opts Options) *Store {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	s := &Store{
		opts:        opts,
		authorities: map[string]bool{},
		records:     map[slotKey]*Record{},
		deletedTo:   map[slotKey]uint64{},
		deletedID:   map[string]bool{},
	}
	for _, a := range opts.Authorities {
		s.authorities[a] = true
	}
	s.snap.Store(&Snapshot{byPubkey: map[string]Member{}, conflicts: map[string]bool{}})
	return s
}

// AddSource registers a source whose freshness counts toward the view's.
func (s *Store) AddSource(f Freshness) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sources = append(s.sources, f)
}

func (s *Store) reject(r Rejection) Rejection {
	v, _ := s.stats.LoadOrStore(r, new(atomic.Int64))
	v.(*atomic.Int64).Add(1)
	return r
}

// Rejections returns how many events were refused, by reason.
func (s *Store) Rejections() map[Rejection]int64 {
	out := map[Rejection]int64{}
	s.stats.Range(func(k, v any) bool {
		out[k.(Rejection)] = v.(*atomic.Int64).Load()
		return true
	})
	return out
}

// Ingest verifies and stores events; it returns how many changed the view.
func (s *Store) Ingest(events ...*nip01.Event) int {
	changed := 0
	for _, ev := range events {
		if ev == nil {
			continue
		}
		if s.ingest(ev) == "" {
			changed++
		}
	}
	return changed
}

// ingest returns "" when ev was accepted.
func (s *Store) ingest(ev *nip01.Event) Rejection {
	if ev.Kind != s.opts.Kind && !(s.opts.HonorDeletions && nip09.IsDeletionKind(ev.Kind)) {
		return s.reject(RejectWrongKind)
	}
	if !s.authorities[ev.PubKey] {
		return s.reject(RejectNotAuthority)
	}
	limit := s.opts.Now().Add(s.opts.FutureSkew).Unix()
	if limit < 0 || ev.CreatedAt > uint64(limit) {
		return s.reject(RejectFuture)
	}
	if err := ev.Verify(); err != nil {
		return s.reject(RejectBadSignature)
	}
	if nip09.IsDeletionKind(ev.Kind) {
		return s.ingestDeletion(ev)
	}
	d := firstTag(ev, "d")
	if s.opts.Heartbeat && d == s.opts.HeartbeatD {
		s.mu.Lock()
		defer s.mu.Unlock()
		if ev.CreatedAt <= s.heartbeat {
			return s.reject(RejectStale)
		}
		s.heartbeat = ev.CreatedAt
		return ""
	}
	if !strings.HasPrefix(d, s.opts.DPrefix) || len(d) == len(s.opts.DPrefix) {
		return s.reject(RejectOtherD)
	}
	rec := s.parseRecord(ev, d)

	s.mu.Lock()
	defer s.mu.Unlock()
	key := slotKey{ev.PubKey, d}
	if ev.CreatedAt <= s.deletedTo[key] || s.deletedID[ev.ID] {
		return s.reject(RejectDeleted)
	}
	if cur := s.records[key]; cur != nil && !nip01.Supersedes(ev, cur.event) {
		return s.reject(RejectStale)
	}
	s.records[key] = rec
	s.dirty = true
	return ""
}

func (s *Store) ingestDeletion(ev *nip01.Event) Rejection {
	s.mu.Lock()
	defer s.mu.Unlock()
	applied := false
	for _, t := range ev.Tags {
		if len(t) < 2 {
			continue
		}
		switch t[0] {
		case "a":
			// kind:pubkey:d — an authority may only delete its own records.
			parts := strings.SplitN(t[1], ":", 3)
			if len(parts) != 3 || parts[0] != itoa(s.opts.Kind) || parts[1] != ev.PubKey {
				continue
			}
			key := slotKey{ev.PubKey, parts[2]}
			if ev.CreatedAt > s.deletedTo[key] {
				s.deletedTo[key] = ev.CreatedAt
			}
			if cur := s.records[key]; cur != nil && cur.CreatedAt <= ev.CreatedAt {
				delete(s.records, key)
			}
			applied = true
		case "e":
			for key, cur := range s.records {
				if cur.ID == t[1] && cur.Authority == ev.PubKey {
					delete(s.records, key)
					s.deletedID[t[1]] = true
					applied = true
				}
			}
		}
	}
	if !applied {
		return s.reject(RejectOtherD)
	}
	s.dirty = true
	return ""
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func firstTag(ev *nip01.Event, name string) string {
	for _, t := range ev.Tags {
		if len(t) >= 2 && t[0] == name {
			return t[1]
		}
	}
	return ""
}

type content struct {
	Name   *string `json:"name"`
	Pubkey string  `json:"pubkey"`
	Status string  `json:"status"`
}

// parseRecord reads ev's content. A record the authority signed but that
// can't be read is kept as invalid: it supersedes older versions and
// grants nothing, so a broken update fails closed.
func (s *Store) parseRecord(ev *nip01.Event, d string) *Record {
	rec := &Record{
		Authority: ev.PubKey, D: d, Name: strings.TrimPrefix(d, s.opts.DPrefix),
		Status: statusInvalid, CreatedAt: ev.CreatedAt, ID: ev.ID, event: ev,
	}
	var c content
	if err := json.Unmarshal([]byte(ev.Content), &c); err != nil {
		return rec
	}
	if c.Status != StatusAlive && c.Status != StatusDead {
		return rec
	}
	if c.Name == nil || *c.Name != rec.Name {
		if s.opts.NameMismatch != "useD" {
			return rec
		}
	}
	if c.Pubkey != "" {
		pub, err := nip19.ParsePublicKey(c.Pubkey)
		if err != nil || strings.HasPrefix(strings.ToLower(c.Pubkey), "nsec") {
			return rec
		}
		rec.Pubkey = pub
	}
	rec.Status = c.Status
	return rec
}

// rebuild resolves records into a new snapshot. Callers hold s.mu.
func (s *Store) rebuild() {
	bySlot := map[string][]*Record{}
	for k, r := range s.records {
		bySlot[k.d] = append(bySlot[k.d], r)
	}
	type claim struct {
		member Member
		at     uint64
	}
	claims := map[string][]claim{}
	for _, recs := range bySlot {
		win := s.resolve(recs)
		if win == nil || win.Status != StatusAlive || win.Pubkey == "" {
			continue
		}
		claims[win.Pubkey] = append(claims[win.Pubkey], claim{
			member: Member{Name: win.Name, Pubkey: win.Pubkey, Since: time.Unix(int64(win.CreatedAt), 0)},
			at:     win.CreatedAt,
		})
	}
	snap := &Snapshot{byPubkey: map[string]Member{}, conflicts: map[string]bool{}, Records: len(s.records)}
	for pub, cs := range claims {
		if len(cs) == 1 {
			snap.byPubkey[pub] = cs[0].member
			continue
		}
		snap.conflicts[pub] = true
		if s.opts.DuplicatePubkey == "newestWins" {
			slices.SortFunc(cs, func(a, b claim) int {
				if a.at != b.at {
					return int(int64(b.at) - int64(a.at))
				}
				return strings.Compare(a.member.Name, b.member.Name)
			})
			if cs[0].at != cs[1].at {
				snap.byPubkey[pub] = cs[0].member
			}
		}
	}
	snap.Size, snap.Conflicts = len(snap.byPubkey), len(snap.conflicts)
	s.snap.Store(snap)
	s.dirty = false
}

// resolve picks the winning record of one slot across authorities.
func (s *Store) resolve(recs []*Record) *Record {
	if s.opts.Resolve == "deadWins" {
		for _, r := range recs {
			if r.Status != StatusAlive {
				return r
			}
		}
	}
	var best *Record
	for _, r := range recs {
		if best == nil || nip01.Supersedes(r.event, best.event) {
			best = r
		}
	}
	return best
}

// Snapshot returns the current view, rebuilding it if records changed.
func (s *Store) Snapshot() *Snapshot {
	s.mu.Lock()
	if s.dirty {
		s.rebuild()
	}
	s.mu.Unlock()
	return s.snap.Load()
}

// Fresh reports whether the view is current: from the heartbeat when
// enabled, otherwise from the freshest source.
func (s *Store) Fresh() bool {
	now := s.opts.Now()
	s.mu.Lock()
	hb, sources := s.heartbeat, slices.Clone(s.sources)
	s.mu.Unlock()
	if s.opts.Heartbeat {
		return hb > 0 && now.Sub(time.Unix(int64(hb), 0)) < s.opts.StaleAfter
	}
	for _, src := range sources {
		if last := src.LastSync(); !last.IsZero() && now.Sub(last) < s.opts.StaleAfter {
			return true
		}
	}
	return false
}

// HeartbeatAge returns how old the newest heartbeat is, or -1 if none.
func (s *Store) HeartbeatAge() time.Duration {
	s.mu.Lock()
	hb := s.heartbeat
	s.mu.Unlock()
	if hb == 0 {
		return -1
	}
	return s.opts.Now().Sub(time.Unix(int64(hb), 0))
}

// Lookup answers whether pubkey is a member, applying onStale.
func (s *Store) Lookup(pubkey string) Lookup {
	snap := s.Snapshot()
	fresh := s.Fresh()
	l := Lookup{Stale: !fresh, Conflict: snap.conflicts[pubkey]}
	if !fresh {
		switch s.opts.OnStale {
		case "denyAll":
			l.DenyAll = true
			return l
		case "denyMembers":
			return l
		}
	}
	if m, ok := snap.byPubkey[pubkey]; ok {
		l.Name = m.Name
	}
	return l
}

// Member returns the resolved member for pubkey regardless of freshness.
func (snap *Snapshot) Member(pubkey string) (Member, bool) {
	m, ok := snap.byPubkey[pubkey]
	return m, ok
}
