package membership

import (
	"testing"
	"time"
)

const quotaPrefix = "quota:"

func quotaStore() *Store {
	s, _ := newStore(func(o *Options) { o.QuotaDPrefix = quotaPrefix })
	return s
}

func TestSignedQuota(t *testing.T) {
	s := quotaStore()
	if n := s.Ingest(auth1.Quota(kind, quotaPrefix, "alice", "50GiB", t0)); n != 1 {
		t.Fatalf("authority quota not accepted (%d)", n)
	}
	if q, ok := s.Snapshot().Quota("alice"); !ok || q != 50<<30 {
		t.Fatalf("alice quota = %d %v", q, ok)
	}
	// A key that isn't an authority changes nothing.
	if n := s.Ingest(mallory.Quota(kind, quotaPrefix, "alice", "1TiB", t0.Add(time.Second))); n != 0 {
		t.Fatal("non-authority quota accepted")
	}
	if q, _ := s.Snapshot().Quota("alice"); q != 50<<30 {
		t.Fatalf("non-authority quota applied: %d", q)
	}
	// The newest record wins across authorities, and a number of bytes works.
	ev := auth2.Sign(kind, t0.Add(2*time.Second), `{"name":"alice","quota":1000}`, []string{"d", "quota:alice"})
	s.Ingest(ev)
	if q, _ := s.Snapshot().Quota("alice"); q != 1000 {
		t.Fatalf("newer quota not applied: %d", q)
	}
	// Quota records are not members.
	if snap := s.Snapshot(); snap.Size != 0 || snap.Records != 0 {
		t.Fatalf("quota records counted as members: %+v", snap)
	}
}

func TestUnreadableQuotaFallsBackToConfig(t *testing.T) {
	s := quotaStore()
	s.Ingest(auth1.Quota(kind, quotaPrefix, "alice", "50GiB", t0))
	for i, content := range []string{`{"name":"alice","quota":"lots"}`, `{"name":"bob","quota":"1GiB"}`, `{"name":"alice","quota":0}`, `not json`} {
		s.Ingest(auth1.Sign(kind, t0.Add(time.Duration(i+1)*time.Second), content, []string{"d", "quota:alice"}))
		if _, ok := s.Snapshot().Quota("alice"); ok {
			t.Fatalf("%s: unreadable record still sets a quota", content)
		}
	}
}

func TestQuotaDeletion(t *testing.T) {
	s := quotaStore()
	ev := auth1.Quota(kind, quotaPrefix, "alice", "50GiB", t0)
	s.Ingest(ev)
	s.Ingest(auth1.Sign(5, t0.Add(time.Second), "", []string{"a", "30078:" + auth1.Pub + ":quota:alice"}))
	if _, ok := s.Snapshot().Quota("alice"); ok {
		t.Fatal("deleted quota record still applies")
	}
}

func TestQuotaRecordsOffWithoutPrefix(t *testing.T) {
	s, _ := newStore(nil)
	if n := s.Ingest(auth1.Quota(kind, quotaPrefix, "alice", "50GiB", t0)); n != 0 {
		t.Fatal("quota record accepted with the quota module off")
	}
	if s.Rejections()[RejectOtherD] != 1 {
		t.Fatalf("rejections: %v", s.Rejections())
	}
}
