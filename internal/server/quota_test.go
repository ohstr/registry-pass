package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/registry-pass/internal/grants"
	"github.com/ohstr/registry-pass/internal/quota"
)

// emptyRegistry has no repositories, so a rebuild completes at once.
func emptyRegistry(t *testing.T) *quota.Registry {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"repositories":[]}`))
	}))
	t.Cleanup(srv.Close)
	base, _ := url.Parse(srv.URL)
	return &quota.Registry{Base: base, Client: srv.Client(), Mint: func([]grants.Access) (string, error) { return "t", nil }}
}

type quotaHarness struct {
	*harness
	q  *quota.Module
	st *quota.Store
}

func newQuotaHarness(t *testing.T, ready bool) *quotaHarness {
	t.Helper()
	st, err := quota.Open(filepath.Join(t.TempDir(), "quota.db"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	q := quota.New(quota.Options{Store: st, Registry: emptyRegistry(t), EventsToken: "events-secret",
		Limits: quota.Limits{Default: 1000, ExemptKeys: map[string]bool{builder.Pub: true}}})
	if ready {
		if _, err := q.Rebuild(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	h := newHarnessDeps(t, nil, "", func(d *Deps) { d.Quota = q })
	return &quotaHarness{harness: h, q: q, st: st}
}

func (h *quotaHarness) call(method, path, auth string, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("X-Forwarded-Proto", "https")
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	w := httptest.NewRecorder()
	h.h.ServeHTTP(w, r)
	return w
}

func warnings(t *testing.T, w *httptest.ResponseRecorder) []string {
	var b struct{ Warnings []string }
	json.Unmarshal(w.Body.Bytes(), &b)
	return b.Warnings
}

func TestTokenDropsPushOverQuota(t *testing.T) {
	h := newQuotaHarness(t, true)
	pw := loginPW(alice, 30*time.Minute)
	scope := q("repository:alice/app:pull,push,delete")

	// Under quota: the token is as without the module.
	w := h.do(req{query: scope, user: alice.Npub, pw: pw})
	if _, c := claims(t, w); strings.Join(granted(c), " ") != "repository:alice/app:pull,push" || warnings(t, w) != nil {
		t.Fatalf("under quota: %v %s", granted(c), w.Body)
	}
	h.st.SetRepo("alice/app", map[string]int64{"sha256:a": 600, "sha256:b": 400}) // exactly at quota
	w = h.do(req{query: scope, user: alice.Npub, pw: pw})
	if _, c := claims(t, w); strings.Join(granted(c), " ") != "repository:alice/app:pull" {
		t.Fatalf("at quota: %v", granted(c))
	}
	want := "namespace alice: 1000B of 1000B used — push refused; delete images to free space"
	if ws := warnings(t, w); len(ws) != 1 || ws[0] != want {
		t.Fatalf("warnings %v", ws)
	}
	if !strings.Contains(h.logs.String(), want) {
		t.Fatalf("no log line: %s", h.logs)
	}

	// An exempt key still pushes; other namespaces are unaffected.
	w = h.do(req{query: q("repository:bodies/x:pull,push"), user: builder.Npub, pw: loginPW(builder, 30*time.Minute)})
	if _, c := claims(t, w); strings.Join(granted(c), " ") != "repository:bodies/x:pull,push" {
		t.Fatalf("exempt key: %v", granted(c))
	}
	// Deleting brings push back at the next token.
	h.st.SetRepo("alice/app", map[string]int64{"sha256:a": 600})
	w = h.do(req{query: scope, user: alice.Npub, pw: pw})
	if _, c := claims(t, w); strings.Join(granted(c), " ") != "repository:alice/app:pull,push" {
		t.Fatalf("after delete: %v", granted(c))
	}
}

func TestTokenUncappedUntilUsageKnown(t *testing.T) {
	h := newQuotaHarness(t, false)
	h.st.SetRepo("alice/app", map[string]int64{"sha256:a": 5000})
	w := h.do(req{query: q("repository:alice/app:pull,push"), user: alice.Npub, pw: loginPW(alice, 30*time.Minute)})
	if _, c := claims(t, w); strings.Join(granted(c), " ") != "repository:alice/app:pull,push" {
		t.Fatalf("capped before the first rebuild: %v", granted(c))
	}
}

func TestEventsEndpoint(t *testing.T) {
	h := newQuotaHarness(t, true)
	env := `{"events":[{"action":"push","target":{"mediaType":"application/vnd.oci.image.manifest.v1+json","repository":"alice/app"}}]}`
	for _, c := range []struct {
		method, auth string
		code         int
	}{
		{"GET", "Bearer events-secret", 405},
		{"POST", "", 401},
		{"POST", "Bearer wrong", 401},
		{"POST", "Basic ZXZlbnRzLXNlY3JldA==", 401},
		{"POST", "Bearer events-secret", 200},
	} {
		if w := h.call(c.method, EventsPath, c.auth, env); w.Code != c.code {
			t.Errorf("%s %q: %d, want %d", c.method, c.auth, w.Code, c.code)
		}
	}
	if h.q.Pending() != 1 {
		t.Fatalf("pending %d", h.q.Pending())
	}
	if w := h.call("POST", EventsPath, "Bearer events-secret", "{"); w.Code != 400 {
		t.Fatalf("bad envelope: %d", w.Code)
	}
	if w := h.call("POST", RebuildPath, "Bearer wrong", ""); w.Code != 401 {
		t.Fatalf("rebuild without the token: %d", w.Code)
	}
	if w := h.call("POST", RebuildPath, "Bearer events-secret", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"repositories":0`) {
		t.Fatalf("rebuild: %d %s", w.Code, w.Body)
	}
}

func TestUsageEndpoint(t *testing.T) {
	h := newQuotaHarness(t, true)
	h.st.SetRepo("alice/app", map[string]int64{"sha256:a": 600, "sha256:b": 100})
	h.st.SetRepo("alice/web", map[string]int64{"sha256:a": 600})
	basic := func(user, pw string) string {
		r := httptest.NewRequest("GET", "/", nil)
		r.SetBasicAuth(user, pw)
		return r.Header.Get("Authorization")
	}
	owner := basic(alice.Npub, loginPW(alice, 30*time.Minute))
	w := h.call("GET", UsagePath+"alice", owner, "")
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != `{"used":700,"quota":1000,"blobs":2}` {
		t.Fatalf("owner: %d %s", w.Code, w.Body)
	}
	// bob holds a read-all (catalog) key; mallory is denied; builder is
	// neither owner nor read-all.
	if w := h.call("GET", UsagePath+"alice", basic(bob.Npub, loginPW(bob, 30*time.Minute)), ""); w.Code != 200 {
		t.Fatalf("read-all: %d %s", w.Code, w.Body)
	}
	for name, c := range map[string]struct {
		path, auth string
		code       int
	}{
		"other key":     {UsagePath + "alice", basic(builder.Npub, loginPW(builder, 30*time.Minute)), 403},
		"denied key":    {UsagePath + "alice", basic(mallory.Npub, loginPW(mallory, 30*time.Minute)), 403},
		"other ns":      {UsagePath + "bob", owner, 403},
		"anonymous":     {UsagePath + "alice", "", 401},
		"static user":   {UsagePath + "alice", basic("node-pull", "pull-secret"), 401},
		"bad login":     {UsagePath + "alice", basic(alice.Npub, "nope"), 401},
		"bad name":      {UsagePath + "Alice", owner, 404},
		"nested":        {UsagePath + "alice/app", owner, 404},
		"empty":         {UsagePath, owner, 404},
		"wrong service": {UsagePath + "alice?service=other", owner, 400},
	} {
		if w := h.call("GET", c.path, c.auth, ""); w.Code != c.code {
			t.Errorf("%s: %d, want %d: %s", name, w.Code, c.code, w.Body)
		}
	}
	if w := h.call("POST", UsagePath+"alice", owner, ""); w.Code != 405 {
		t.Fatal("POST /usage")
	}

	notReady := newQuotaHarness(t, false)
	if w := notReady.call("GET", UsagePath+"alice", owner, ""); w.Code != 503 {
		t.Fatalf("before the first rebuild: %d", w.Code)
	}
}

func TestQuotaMetrics(t *testing.T) {
	h := newQuotaHarness(t, true)
	h.st.SetRepo("alice/app", map[string]int64{"sha256:a": 700})
	w := h.call("GET", "/metrics", "", "")
	for _, m := range []string{`registry_pass_quota_used_bytes{name="alice"} 700`, `registry_pass_quota_bytes{name="alice"} 1000`, "registry_pass_quota_ready 1"} {
		if !strings.Contains(w.Body.String(), m) {
			t.Errorf("metrics missing %s", m)
		}
	}
}

// TestModuleOffIsUnchanged: without the module there are no quota routes,
// metrics or token fields (criterion 7).
func TestModuleOffIsUnchanged(t *testing.T) {
	h := &quotaHarness{harness: newHarness(t, nil, "")}
	for _, p := range []string{EventsPath, UsagePath + "alice", RebuildPath} {
		if w := h.call("POST", p, "Bearer x", "{}"); w.Code != 404 {
			t.Errorf("%s: %d with the module off", p, w.Code)
		}
	}
	w := h.do(req{query: q("repository:alice/app:pull,push"), user: alice.Npub, pw: loginPW(alice, 30*time.Minute)})
	if strings.Contains(w.Body.String(), "warnings") {
		t.Fatalf("token body changed: %s", w.Body)
	}
	w = h.call("GET", "/metrics", "", "")
	if strings.Contains(w.Body.String(), "registry_pass_quota") {
		t.Fatal("quota metrics with the module off")
	}
}
