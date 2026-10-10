package membership

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

func jsonl(t *testing.T, events ...*nip01.Event) string {
	var b strings.Builder
	b.WriteString("# membership feed\n\n")
	for _, ev := range events {
		data, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(data)
		b.WriteByte('\n')
	}
	return b.String()
}

func liveStore() *Store {
	return New(Options{
		Authorities: []string{auth1.Pub}, Kind: kind, DPrefix: prefix, NameMismatch: "reject",
		Resolve: "latest", FutureSkew: 30 * time.Second, HonorDeletions: true,
		DuplicatePubkey: "denyAll", StaleAfter: time.Minute, OnStale: "denyMembers",
	})
}

func TestFileSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "members.jsonl")
	now := time.Now()
	os.WriteFile(path, []byte(jsonl(t, member(auth1, "alice", alice, "alive", now))), 0o600)

	s := liveStore()
	f := &FileSource{Path: path, Watch: true, PollInterval: time.Hour}
	s.AddSource(f)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error)
	go func() { done <- f.Run(ctx, s) }()

	waitFor(t, func() bool { return name(s, alice) == "alice" })
	if f.LastSync().IsZero() || !s.Fresh() {
		t.Fatal("file read did not count as a sync")
	}

	// The authority revokes alice; an atomic replace (as a ConfigMap
	// update does) must be picked up by the watcher.
	tmp := filepath.Join(dir, "members.tmp")
	os.WriteFile(tmp, []byte(jsonl(t, member(auth1, "alice", alice, "dead", now.Add(time.Second)))), 0o600)
	os.Rename(tmp, path)
	waitFor(t, func() bool { return name(s, alice) == "" })

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestFileSourceBadContentKeepsLastGoodView(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "members.jsonl")
	os.WriteFile(path, []byte(jsonl(t, member(auth1, "alice", alice, "alive", time.Now()))), 0o600)
	s := liveStore()
	f := &FileSource{Path: path, PollInterval: time.Hour}
	s.AddSource(f)
	if err := f.ReadOnce(s); err != nil {
		t.Fatal(err)
	}
	first := f.LastSync()

	os.WriteFile(path, []byte("{not json\n"), 0o600)
	if err := f.ReadOnce(s); err == nil {
		t.Fatal("corrupt file accepted")
	}
	if f.LastSync() != first || f.LastError() == nil {
		t.Fatal("a failed read must not count as a sync")
	}
	if name(s, alice) != "alice" {
		t.Fatal("a corrupt file must not wipe the view")
	}

	os.Remove(path)
	if err := f.ReadOnce(s); err == nil {
		t.Fatal("missing file accepted")
	}
	if _, err := readJSONL(filepath.Join(dir, "nope")); err == nil {
		t.Fatal("readJSONL")
	}
	long := filepath.Join(dir, "long.jsonl")
	os.WriteFile(long, []byte(strings.Repeat("a", maxLine+10)), 0o600)
	if _, err := readJSONL(long); err == nil {
		t.Fatal("over-long line accepted")
	}
}

func TestHTTPSource(t *testing.T) {
	var hits atomic.Int32
	var gotAuth atomic.Value
	events := []*nip01.Event{member(auth1, "alice", alice, "alive", time.Now()), member(mallory, "mallory", mallory, "alive", time.Now())}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		gotAuth.Store(r.Header.Get("Authorization"))
		json.NewEncoder(w).Encode(events)
	}))
	defer srv.Close()

	s := liveStore()
	h := &HTTPSource{
		URL: srv.URL, Interval: time.Hour, Timeout: 5 * time.Second,
		Headers: func() (http.Header, error) { return http.Header{"Authorization": {"Bearer t"}}, nil },
	}
	s.AddSource(h)
	if err := h.FetchOnce(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if name(s, alice) != "alice" || name(s, mallory) != "" {
		t.Fatal("feed not applied, or a non-authority record accepted")
	}
	if gotAuth.Load() != "Bearer t" || !s.Fresh() {
		t.Fatal("headers or freshness")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- h.Run(ctx, s) }()
	waitFor(t, func() bool { return hits.Load() >= 2 })
	cancel()
	<-done
}

func TestHTTPSourceFailures(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"500":      func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) },
		"not json": func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>")) },
		"object":   func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"a":1}`)) },
		"slow": func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-time.After(2 * time.Second):
			case <-r.Context().Done():
			}
		},
	}
	for label, handler := range cases {
		srv := httptest.NewServer(handler)
		h := &HTTPSource{URL: srv.URL, Timeout: 200 * time.Millisecond}
		s := liveStore()
		if err := h.FetchOnce(context.Background(), s); err == nil {
			t.Errorf("%s: accepted", label)
		}
		if !h.LastSync().IsZero() {
			t.Errorf("%s: failure counted as a sync", label)
		}
		srv.Close()
	}
	h := &HTTPSource{URL: "http://x", Timeout: time.Second, Headers: func() (http.Header, error) { return nil, os.ErrNotExist }}
	if err := h.FetchOnce(context.Background(), liveStore()); err == nil {
		t.Fatal("header error ignored")
	}
}

func TestHTTPSourceDoesNotFollowRedirects(t *testing.T) {
	var leaked atomic.Bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked.Store(true)
		}
		w.Write([]byte("[]"))
	}))
	defer evil.Close()
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL, http.StatusFound)
	}))
	defer feed.Close()
	client, err := NewHTTPClient("", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	h := &HTTPSource{URL: feed.URL, Timeout: time.Second, Client: client,
		Headers: func() (http.Header, error) { return http.Header{"Authorization": {"Bearer secret"}}, nil }}
	if err := h.FetchOnce(context.Background(), liveStore()); err == nil {
		t.Fatal("redirect response accepted as a feed")
	}
	if leaked.Load() {
		t.Fatal("credentials followed a redirect")
	}
}

func TestNewHTTPClientCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("[]")) }))
	defer srv.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(ca, pemCert(srv.Certificate().Raw), 0o600)
	client, err := NewHTTPClient(ca, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	h := &HTTPSource{URL: srv.URL, Timeout: time.Second, Client: client}
	if err := h.FetchOnce(context.Background(), liveStore()); err != nil {
		t.Fatalf("custom CA not trusted: %v", err)
	}
	plain, _ := NewHTTPClient("", time.Second)
	h.Client = plain
	if err := h.FetchOnce(context.Background(), liveStore()); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	if _, err := NewHTTPClient(filepath.Join(t.TempDir(), "none"), time.Second); err == nil {
		t.Fatal("missing CA file accepted")
	}
	bad := filepath.Join(t.TempDir(), "bad.pem")
	os.WriteFile(bad, []byte("nope"), 0o600)
	if _, err := NewHTTPClient(bad, time.Second); err == nil {
		t.Fatal("CA file without certificates accepted")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}
