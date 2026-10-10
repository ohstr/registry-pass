package membership

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/registry-pass/internal/testkit"
)

const (
	kind   = 30078
	prefix = "member:"
)

var (
	auth1   = testkit.NewKey("authority-1")
	auth2   = testkit.NewKey("authority-2")
	alice   = testkit.NewKey("alice")
	bob     = testkit.NewKey("bob")
	mallory = testkit.NewKey("mallory")
	t0      = time.Unix(1_800_000_000, 0)
)

type fixedSource struct{ at time.Time }

func (f fixedSource) LastSync() time.Time { return f.at }

func newStore(mod func(*Options)) (*Store, *time.Time) {
	clock := t0
	o := Options{
		Authorities: []string{auth1.Pub, auth2.Pub}, Kind: kind, DPrefix: prefix,
		NameMismatch: "reject", Resolve: "latest", FutureSkew: 30 * time.Second,
		HonorDeletions: true, DuplicatePubkey: "denyAll", StaleAfter: 30 * time.Minute,
		OnStale: "denyMembers", HeartbeatD: "registry-pass:heartbeat",
		Now: func() time.Time { return clock },
	}
	if mod != nil {
		mod(&o)
	}
	s := New(o)
	s.AddSource(fixedSource{at: t0})
	return s, &clock
}

func member(a testkit.Key, name string, k testkit.Key, status string, at time.Time) *nip01.Event {
	return a.Member(kind, prefix, name, k.Pub, status, at)
}

func name(s *Store, k testkit.Key) string { return s.Lookup(k.Pub).Name }

func TestAliveDeadAndEmpty(t *testing.T) {
	s, _ := newStore(nil)
	s.Ingest(
		member(auth1, "alice", alice, "alive", t0),
		member(auth1, "bob", bob, "dead", t0),
		auth1.Member(kind, prefix, "carol", "", "alive", t0),
	)
	if name(s, alice) != "alice" {
		t.Fatal("alive member missing")
	}
	if name(s, bob) != "" {
		t.Fatal("dead member resolved")
	}
	snap := s.Snapshot()
	if snap.Size != 1 || snap.Records != 3 {
		t.Fatalf("size %d records %d", snap.Size, snap.Records)
	}
}

func TestForgedEventsChangeNothing(t *testing.T) {
	s, _ := newStore(nil)
	// mallory signs a record claiming membership.
	s.Ingest(member(mallory, "mallory", mallory, "alive", t0))
	// mallory claims to be the authority but signs with her own key.
	forged := member(mallory, "mallory2", mallory, "alive", t0)
	forged.PubKey = auth1.Pub
	s.Ingest(forged)
	// an authority's record with content tampered after signing.
	tampered := member(auth1, "alice", alice, "dead", t0)
	tampered.Content = strings.Replace(tampered.Content, "dead", "alive", 1)
	s.Ingest(tampered)
	if name(s, mallory) != "" || name(s, alice) != "" {
		t.Fatal("forged record accepted")
	}
	r := s.Rejections()
	if r[RejectNotAuthority] != 1 || r[RejectBadSignature] != 2 {
		t.Fatalf("rejections %v", r)
	}
}

func TestReplayCannotUndoRevocation(t *testing.T) {
	s, _ := newStore(nil)
	alive := member(auth1, "alice", alice, "alive", t0.Add(-time.Hour))
	dead := member(auth1, "alice", alice, "dead", t0.Add(-time.Minute))
	s.Ingest(alive, dead)
	if name(s, alice) != "" {
		t.Fatal("revocation not applied")
	}
	s.Ingest(alive) // a stale source replays the older alive version
	if name(s, alice) != "" {
		t.Fatal("replayed older event resurrected a revoked member")
	}
	if s.Rejections()[RejectStale] == 0 {
		t.Fatal("replay not counted")
	}
	// Order of arrival doesn't matter.
	s2, _ := newStore(nil)
	s2.Ingest(dead, alive)
	if name(s2, alice) != "" {
		t.Fatal("arrival order changed the outcome")
	}
}

func TestSameSecondTieBreaksOnLowestID(t *testing.T) {
	s, _ := newStore(nil)
	a := member(auth1, "alice", alice, "alive", t0)
	d := member(auth1, "alice", alice, "dead", t0)
	s.Ingest(a, d)
	want := "alice"
	if d.ID < a.ID {
		want = ""
	}
	if name(s, alice) != want {
		t.Fatalf("tie not resolved by lowest id")
	}
}

func TestFutureDatedEventsIgnored(t *testing.T) {
	s, _ := newStore(nil)
	// A far-future alive record would otherwise win forever.
	s.Ingest(member(auth1, "alice", alice, "alive", t0.Add(24*time.Hour)))
	if name(s, alice) != "" {
		t.Fatal("future-dated record accepted")
	}
	s.Ingest(member(auth1, "alice", alice, "alive", t0.Add(20*time.Second)))
	if name(s, alice) != "alice" {
		t.Fatal("record within skew refused")
	}
}

func TestInvalidRecordsFailClosed(t *testing.T) {
	cases := map[string]string{
		"not json":       "nope",
		"bad status":     `{"name":"alice","pubkey":"` + alice.Pub + `","status":"admin"}`,
		"name mismatch":  `{"name":"bob","pubkey":"` + alice.Pub + `","status":"alive"}`,
		"missing name":   `{"pubkey":"` + alice.Pub + `","status":"alive"}`,
		"nsec as pubkey": `{"name":"alice","pubkey":"` + alice.Nsec + `","status":"alive"}`,
		"bad pubkey":     `{"name":"alice","pubkey":"xyz","status":"alive"}`,
	}
	for label, c := range cases {
		s, _ := newStore(nil)
		s.Ingest(member(auth1, "alice", alice, "alive", t0.Add(-time.Hour)))
		s.Ingest(auth1.Sign(kind, t0, c, []string{"d", prefix + "alice"}))
		if name(s, alice) != "" {
			t.Errorf("%s: a broken newer record left the older alive one in force", label)
		}
	}
	// useD accepts a mismatching content name, taking the name from d.
	s, _ := newStore(func(o *Options) { o.NameMismatch = "useD" })
	s.Ingest(auth1.Sign(kind, t0, `{"name":"bob","pubkey":"`+alice.Pub+`","status":"alive"}`, []string{"d", prefix + "alice"}))
	if name(s, alice) != "alice" {
		t.Fatal("useD")
	}
}

func TestOtherEventsIgnored(t *testing.T) {
	s, _ := newStore(nil)
	s.Ingest(
		auth1.Sign(1, t0, "hello"),                                  // wrong kind
		auth1.Sign(kind, t0, `{}`, []string{"d", "settings:theme"}), // other app data
		auth1.Sign(kind, t0, `{"name":"","pubkey":"`+alice.Pub+`","status":"alive"}`, []string{"d", prefix}),
		auth1.Sign(kind, t0, `{"name":"alice","pubkey":"`+alice.Pub+`","status":"alive"}`), // no d
	)
	if s.Snapshot().Records != 0 {
		t.Fatal("non-member events stored")
	}
}

func TestDeletions(t *testing.T) {
	s, _ := newStore(nil)
	rec := member(auth1, "alice", alice, "alive", t0.Add(-time.Hour))
	s.Ingest(rec)
	addr := fmt.Sprintf("%d:%s:%salice", kind, auth1.Pub, prefix)

	// Deletions by someone else, or naming another author's record, do nothing.
	s.Ingest(mallory.Sign(5, t0, "", []string{"a", addr}))
	s.Ingest(auth2.Sign(5, t0, "", []string{"a", addr}))
	s.Ingest(auth2.Sign(5, t0, "", []string{"e", rec.ID}))
	if name(s, alice) != "alice" {
		t.Fatal("a deletion not by the record's author removed it")
	}

	s.Ingest(auth1.Sign(5, t0.Add(-time.Minute), "", []string{"a", addr}))
	if name(s, alice) != "" {
		t.Fatal("authority's deletion not applied")
	}
	s.Ingest(rec) // replay of the deleted version
	if name(s, alice) != "" {
		t.Fatal("deleted record came back")
	}
	s.Ingest(member(auth1, "alice", alice, "alive", t0)) // re-added after the deletion
	if name(s, alice) != "alice" {
		t.Fatal("newer record after deletion refused")
	}

	byID, _ := newStore(nil)
	r2 := member(auth1, "bob", bob, "alive", t0.Add(-time.Hour))
	byID.Ingest(r2, auth1.Sign(5, t0, "", []string{"e", r2.ID}))
	if name(byID, bob) != "" {
		t.Fatal("e-tag deletion not applied")
	}
	byID.Ingest(r2)
	if name(byID, bob) != "" {
		t.Fatal("deleted id came back")
	}

	off, _ := newStore(func(o *Options) { o.HonorDeletions = false })
	off.Ingest(rec, auth1.Sign(5, t0, "", []string{"a", addr}))
	if name(off, alice) != "alice" {
		t.Fatal("honorDeletions false still deleted")
	}
}

func TestMultipleAuthorities(t *testing.T) {
	older, newer := t0.Add(-time.Hour), t0.Add(-time.Minute)

	latest, _ := newStore(nil)
	latest.Ingest(member(auth1, "alice", alice, "alive", older), member(auth2, "alice", alice, "dead", newer))
	if name(latest, alice) != "" {
		t.Fatal("latest: newer dead must win")
	}
	latest.Ingest(member(auth2, "bob", bob, "dead", older), member(auth1, "bob", bob, "alive", newer))
	if name(latest, bob) != "bob" {
		t.Fatal("latest: newer alive must win")
	}

	deadWins, _ := newStore(func(o *Options) { o.Resolve = "deadWins" })
	deadWins.Ingest(member(auth2, "bob", bob, "dead", older), member(auth1, "bob", bob, "alive", newer))
	if name(deadWins, bob) != "" {
		t.Fatal("deadWins: any dead must win")
	}
}

func TestDuplicatePubkeys(t *testing.T) {
	deny, _ := newStore(nil)
	deny.Ingest(member(auth1, "alice", alice, "alive", t0.Add(-time.Hour)), member(auth1, "alice2", alice, "alive", t0))
	l := deny.Lookup(alice.Pub)
	if l.Name != "" || !l.Conflict {
		t.Fatalf("denyAll: %+v", l)
	}
	newest, _ := newStore(func(o *Options) { o.DuplicatePubkey = "newestWins" })
	newest.Ingest(member(auth1, "alice", alice, "alive", t0.Add(-time.Hour)), member(auth1, "alice2", alice, "alive", t0))
	if name(newest, alice) != "alice2" {
		t.Fatal("newestWins")
	}
	// Retiring the old record resolves the conflict (a rename).
	deny.Ingest(member(auth1, "alice", alice, "dead", t0))
	if name(deny, alice) != "alice2" {
		t.Fatal("rename not resolved")
	}
}

func TestFreshnessAndOnStale(t *testing.T) {
	for _, mode := range []string{"denyMembers", "denyAll", "keepLastView"} {
		s, clock := newStore(func(o *Options) { o.OnStale = mode })
		s.Ingest(member(auth1, "alice", alice, "alive", t0))
		if l := s.Lookup(alice.Pub); l.Stale || l.Name != "alice" {
			t.Fatalf("%s fresh: %+v", mode, l)
		}
		*clock = t0.Add(31 * time.Minute)
		l := s.Lookup(alice.Pub)
		if !l.Stale {
			t.Fatalf("%s: not stale", mode)
		}
		switch mode {
		case "denyMembers":
			if l.Name != "" || l.DenyAll {
				t.Fatalf("denyMembers: %+v", l)
			}
		case "denyAll":
			if !l.DenyAll {
				t.Fatalf("denyAll: %+v", l)
			}
		case "keepLastView":
			if l.Name != "alice" {
				t.Fatalf("keepLastView: %+v", l)
			}
		}
	}
	none := New(Options{StaleAfter: time.Minute})
	if none.Fresh() {
		t.Fatal("no sources must be stale")
	}
	none.AddSource(fixedSource{})
	if none.Fresh() {
		t.Fatal("a source that never synced must be stale")
	}
}

func TestHeartbeat(t *testing.T) {
	s, clock := newStore(func(o *Options) { o.Heartbeat = true })
	hb := func(k testkit.Key, at time.Time) *nip01.Event {
		return k.Sign(kind, at, "", []string{"d", "registry-pass:heartbeat"})
	}
	if s.Fresh() || s.HeartbeatAge() != -1 {
		t.Fatal("fresh without a heartbeat (sources must not count)")
	}
	s.Ingest(hb(mallory, t0)) // not an authority
	if s.Fresh() {
		t.Fatal("heartbeat from a non-authority counted")
	}
	s.Ingest(hb(auth1, t0.Add(time.Hour))) // future-dated
	if s.Fresh() {
		t.Fatal("future heartbeat counted")
	}
	s.Ingest(hb(auth2, t0.Add(-time.Minute)))
	if !s.Fresh() || s.HeartbeatAge() != time.Minute {
		t.Fatal("authority heartbeat not counted")
	}
	*clock = t0.Add(40 * time.Minute)
	s.Ingest(hb(auth1, t0.Add(-2*time.Minute))) // older than the newest
	if s.Fresh() {
		t.Fatal("an older heartbeat refreshed the view")
	}
}

func TestConcurrentIngestAndLookup(t *testing.T) {
	s, _ := newStore(nil)
	var events []*nip01.Event
	for i := range 50 {
		k := testkit.NewKey(fmt.Sprintf("m%d", i))
		events = append(events, member(auth1, fmt.Sprintf("m%d", i), k, "alive", t0))
	}
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for _, ev := range events[i*6 : min(len(events), i*6+6)] {
				s.Ingest(ev)
			}
		}()
		go func() {
			defer wg.Done()
			for range 50 {
				s.Lookup(alice.Pub)
			}
		}()
	}
	wg.Wait()
	if s.Snapshot().Size != 48 {
		t.Fatalf("size %d", s.Snapshot().Size)
	}
}
