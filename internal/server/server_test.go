package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ohstr/registry-pass/internal/config"
	"github.com/ohstr/registry-pass/internal/grants"
	"github.com/ohstr/registry-pass/internal/login"
	"github.com/ohstr/registry-pass/internal/membership"
	"github.com/ohstr/registry-pass/internal/testkit"
	"github.com/ohstr/registry-pass/internal/token"
	"golang.org/x/crypto/bcrypt"
)

const (
	realm   = "https://pass.example/token"
	service = "registry.example"
)

var (
	authority = testkit.NewKey("authority")
	alice     = testkit.NewKey("alice")
	bob       = testkit.NewKey("bob")
	builder   = testkit.NewKey("builder")
	mallory   = testkit.NewKey("mallory")
)

type syncedAt struct {
	mu sync.Mutex
	at time.Time
}

func (s *syncedAt) Name() string { return "test" }
func (s *syncedAt) LastSync() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.at
}
func (s *syncedAt) set(t time.Time) { s.mu.Lock(); s.at = t; s.mu.Unlock() }

type harness struct {
	srv    *Server
	h      http.Handler
	logs   *bytes.Buffer
	source *syncedAt
	store  *membership.Store
	cfg    *config.Config
}

var pullHash = func() string {
	h, _ := bcrypt.GenerateFromPassword([]byte("pull-secret"), 10)
	return string(h)
}()

func grantsYAML(extra string) string {
	return fmt.Sprintf(`
templates: [{repos: "{name}/**", actions: [pull, push]}]
identities:
  %q: [{repos: "bodies/**", actions: [pull, push]}]
staticUsers:
  node-pull: {bcrypt: %q, grants: [{repos: "**", actions: [pull]}]}
catalog: [%q]
deny: [%q]
`, builder.Npub, pullHash, bob.Npub, mallory.Npub) + extra
}

func newHarness(t *testing.T, mod func(*config.Config), grantsExtra string) *harness {
	t.Helper()
	return newHarnessDeps(t, mod, grantsExtra, nil)
}

func newHarnessDeps(t *testing.T, mod func(*config.Config), grantsExtra string, deps func(*Deps)) *harness {
	t.Helper()
	cfg := config.Default()
	cfg.Realm, cfg.Services = realm, []string{service}
	cfg.Server.TrustedProxies = []string{"10.0.0.0/8"}
	cfg.Membership.Authorities = []string{authority.Pub}
	cfg.RateLimit.Enabled = false
	if mod != nil {
		mod(&cfg)
	}
	v, err := login.New(login.Options{
		Realm: cfg.Realm, Kind: cfg.Login.Kind, MaxLifetime: cfg.Login.MaxLifetime.D(),
		MinRemaining: cfg.Login.MinRemaining.D(), ClockSkew: cfg.Login.ClockSkew.D(), CacheSize: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, certPEM, err := token.Generate("ES256", "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	iss, err := token.New(keyPEM, certPEM, nil, token.Options{Issuer: cfg.Issuer, Algorithm: "ES256", X5C: true, KID: "auto"})
	if err != nil {
		t.Fatal(err)
	}
	pol, err := grants.Parse([]byte(grantsYAML(grantsExtra)), grants.Options{NamePattern: cfg.Grants.NamePattern, AutoReserve: true})
	if err != nil {
		t.Fatal(err)
	}
	m := cfg.Membership
	store := membership.New(membership.Options{
		Authorities: m.Authorities, Kind: m.Kind, DPrefix: m.DPrefix, NameMismatch: m.NameMismatch,
		Resolve: m.Resolve, FutureSkew: m.FutureSkew.D(), HonorDeletions: true, DuplicatePubkey: m.DuplicatePubkey,
		StaleAfter: m.StaleAfter.D(), OnStale: m.OnStale,
	})
	src := &syncedAt{at: time.Now()}
	store.AddSource(src)
	store.Ingest(authority.Member(m.Kind, m.DPrefix, "alice", alice.Pub, "alive", time.Now().Add(-time.Minute)))

	logs := &bytes.Buffer{}
	d := Deps{
		Config: &cfg, Verifier: v, Issuer: iss, Policy: pol, Store: store, Sources: []Source{src},
		Log: slog.New(slog.NewJSONHandler(&lockedWriter{w: logs}, nil)),
	}
	if deps != nil {
		deps(&d)
	}
	srv, err := New(d)
	if err != nil {
		t.Fatal(err)
	}
	return &harness{srv: srv, h: srv.Handler(), logs: logs, source: src, store: store, cfg: &cfg}
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

type req struct {
	method   string
	query    string
	user, pw string
	auth     string
	remote   string
	headers  map[string]string
}

func (h *harness) do(r req) *httptest.ResponseRecorder {
	if r.method == "" {
		r.method = http.MethodGet
	}
	if r.remote == "" {
		r.remote = "10.0.0.1:1234"
		if r.headers == nil {
			r.headers = map[string]string{}
		}
		if _, ok := r.headers["X-Forwarded-Proto"]; !ok {
			r.headers["X-Forwarded-Proto"] = "https"
		}
		if _, ok := r.headers["X-Forwarded-For"]; !ok {
			r.headers["X-Forwarded-For"] = "203.0.113.7"
		}
	}
	hr := httptest.NewRequest(r.method, "/token?"+r.query, nil)
	hr.RemoteAddr = r.remote
	for k, v := range r.headers {
		hr.Header.Set(k, v)
	}
	if r.auth != "" {
		hr.Header.Set("Authorization", r.auth)
	} else if r.user != "" || r.pw != "" {
		hr.SetBasicAuth(r.user, r.pw)
	}
	w := httptest.NewRecorder()
	h.h.ServeHTTP(w, hr)
	return w
}

func q(scopes ...string) string {
	v := url.Values{"service": {service}}
	for _, s := range scopes {
		v.Add("scope", s)
	}
	return v.Encode()
}

func loginPW(k testkit.Key, life time.Duration) string {
	return testkit.Password(k.LoginEvent(realm, time.Now(), life))
}

type tokenBody struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	IssuedAt    string `json:"issued_at"`
}

func claims(t *testing.T, w *httptest.ResponseRecorder) (tokenBody, map[string]any) {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var b tokenBody
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if b.Token == "" || b.Token != b.AccessToken {
		t.Fatal("token and access_token must both be set")
	}
	parts := strings.Split(b.Token, ".")
	data, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c map[string]any
	json.Unmarshal(data, &c)
	return b, c
}

func granted(c map[string]any) []string {
	var out []string
	acc, _ := c["access"].([]any)
	for _, a := range acc {
		m := a.(map[string]any)
		var acts []string
		for _, x := range m["actions"].([]any) {
			acts = append(acts, x.(string))
		}
		out = append(out, m["type"].(string)+":"+m["name"].(string)+":"+strings.Join(acts, ","))
	}
	return out
}

func TestMemberTokenFlow(t *testing.T) {
	h := newHarness(t, nil, "")
	w := h.do(req{query: q("repository:alice/app:pull,push", "repository:bob/app:pull"), user: alice.Npub, pw: loginPW(alice, 30*time.Minute)})
	b, c := claims(t, w)
	if got := granted(c); len(got) != 1 || got[0] != "repository:alice/app:pull,push" {
		t.Fatalf("granted %v", got)
	}
	if c["sub"] != alice.Pub || c["aud"] != service || c["iss"] != "registry-pass" {
		t.Fatalf("claims %v", c)
	}
	if b.ExpiresIn != 300 || b.IssuedAt == "" {
		t.Fatalf("expires_in %d", b.ExpiresIn)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("token response must not be cached")
	}
}

func TestDockerLoginProbe(t *testing.T) {
	h := newHarness(t, nil, "")
	query := url.Values{"service": {service}, "account": {alice.Npub}, "client_id": {"docker"}, "offline_token": {"true"}}.Encode()
	_, c := claims(t, h.do(req{query: query, user: alice.Npub, pw: loginPW(alice, 30*time.Minute)}))
	if len(granted(c)) != 0 {
		t.Fatal("a probe must grant nothing")
	}
	mismatch := url.Values{"service": {service}, "account": {bob.Npub}}.Encode()
	if w := h.do(req{query: mismatch, user: alice.Npub, pw: loginPW(alice, 30*time.Minute)}); w.Code != http.StatusUnauthorized {
		t.Fatalf("account mismatch: %d", w.Code)
	}
}

func TestRequestValidation(t *testing.T) {
	h := newHarness(t, nil, "")
	pw := loginPW(alice, 30*time.Minute)
	cases := map[string]struct {
		r    req
		code int
	}{
		"unknown service":  {req{query: "service=evil.example", user: alice.Npub, pw: pw}, 400},
		"missing service":  {req{query: "", user: alice.Npub, pw: pw}, 400},
		"service twice":    {req{query: "service=" + service + "&service=" + service, user: alice.Npub, pw: pw}, 400},
		"no credentials":   {req{query: q()}, 401},
		"not basic":        {req{query: q(), auth: "Bearer abc"}, 401},
		"empty user":       {req{query: q(), user: "", pw: "x"}, 401},
		"bad login":        {req{query: q(), user: alice.Npub, pw: "garbage"}, 401},
		"someone's event":  {req{query: q(), user: bob.Npub, pw: pw}, 401},
		"nsec as username": {req{query: q(), user: alice.Nsec, pw: pw}, 401},
		"POST":             {req{method: "POST", query: q()}, 404},
		"PUT":              {req{method: "PUT", query: q()}, 405},
		"too many scopes":  {req{query: q(strings.Split(strings.Repeat("repository:a/b:pull ", 65), " ")[:65]...), user: alice.Npub, pw: pw}, 400},
	}
	for name, tc := range cases {
		w := h.do(tc.r)
		if w.Code != tc.code {
			t.Errorf("%s: status %d, want %d (%s)", name, w.Code, tc.code, w.Body)
		}
		if tc.code == 401 && w.Header().Get("WWW-Authenticate") != `Basic realm="registry-pass"` {
			t.Errorf("%s: missing Basic challenge", name)
		}
		if tc.code >= 400 && tc.code != 404 && !strings.Contains(w.Body.String(), `"errors"`) {
			t.Errorf("%s: error body is not JSON: %s", name, w.Body)
		}
	}
	h2 := newHarness(t, func(c *config.Config) { c.Server.PostToken = "methodNotAllowed" }, "")
	if w := h2.do(req{method: "POST", query: q()}); w.Code != 405 {
		t.Fatalf("postToken methodNotAllowed: %d", w.Code)
	}
}

func TestGrantsThroughTheServer(t *testing.T) {
	h := newHarness(t, nil, `anonymous: [{repos: "public/**", actions: [pull]}]`)
	// A non-member identity gets exactly its grants.
	_, c := claims(t, h.do(req{query: q("repository:bodies/x:pull,push", "repository:builder/x:push"), user: builder.Npub, pw: loginPW(builder, 30*time.Minute)}))
	if g := granted(c); len(g) != 1 || g[0] != "repository:bodies/x:pull,push" {
		t.Fatalf("builder %v", g)
	}
	// The static pull user pulls everything, pushes nothing.
	_, c = claims(t, h.do(req{query: q("repository:any/x:pull,push"), user: "node-pull", pw: "pull-secret"}))
	if g := granted(c); len(g) != 1 || g[0] != "repository:any/x:pull" {
		t.Fatalf("static %v", g)
	}
	if w := h.do(req{query: q(), user: "node-pull", pw: "wrong"}); w.Code != 401 {
		t.Fatalf("static wrong password: %d", w.Code)
	}
	// Catalog only for listed pubkeys.
	_, c = claims(t, h.do(req{query: q("registry:catalog:*"), user: bob.Npub, pw: loginPW(bob, 30*time.Minute)}))
	if g := granted(c); len(g) != 1 {
		t.Fatalf("catalog %v", g)
	}
	_, c = claims(t, h.do(req{query: q("registry:catalog:*"), user: alice.Npub, pw: loginPW(alice, 30*time.Minute)}))
	if len(granted(c)) != 0 {
		t.Fatal("catalog granted to an unlisted pubkey")
	}
	// Anonymous pull of public repositories only.
	_, c = claims(t, h.do(req{query: q("repository:public/x:pull,push", "repository:alice/x:pull")}))
	if g := granted(c); len(g) != 1 || g[0] != "repository:public/x:pull" {
		t.Fatalf("anonymous %v", g)
	}
	// Denied pubkeys get 403 even with a valid login.
	if w := h.do(req{query: q("repository:mallory/x:pull"), user: mallory.Npub, pw: loginPW(mallory, 30*time.Minute)}); w.Code != 403 {
		t.Fatalf("denied: %d", w.Code)
	}
	// A reload takes effect at once.
	np, _ := grants.Parse([]byte(""), grants.Options{NamePattern: h.cfg.Grants.NamePattern})
	h.srv.SetPolicy(np)
	h.srv.Reloaded(true)
	_, c = claims(t, h.do(req{query: q("repository:alice/app:pull"), user: alice.Npub, pw: loginPW(alice, 30*time.Minute)}))
	if len(granted(c)) != 0 {
		t.Fatal("old policy still applied after reload")
	}
}

func TestTokenLifetimeCappedToLogin(t *testing.T) {
	h := newHarness(t, nil, "")
	b, _ := claims(t, h.do(req{query: q(), user: alice.Npub, pw: loginPW(alice, 4*time.Minute)}))
	if b.ExpiresIn > 240 || b.ExpiresIn < 230 {
		t.Fatalf("expires_in %d, want about 240 (capped to the login)", b.ExpiresIn)
	}
	noCap := newHarness(t, func(c *config.Config) { c.Token.CapToLoginExpiry = false }, "")
	b, _ = claims(t, noCap.do(req{query: q(), user: alice.Npub, pw: loginPW(alice, 4*time.Minute)}))
	if b.ExpiresIn != 300 {
		t.Fatalf("uncapped expires_in %d", b.ExpiresIn)
	}
	short := newHarness(t, func(c *config.Config) { c.Login.MinRemaining = 0 }, "")
	if w := short.do(req{query: q(), user: alice.Npub, pw: loginPW(alice, 30*time.Second)}); w.Code != 401 {
		t.Fatalf("token shorter than minLifetime issued: %d", w.Code)
	}
}

func TestStaleMembership(t *testing.T) {
	stale := func(h *harness) { h.source.set(time.Now().Add(-time.Hour)) }

	h := newHarness(t, nil, "")
	stale(h)
	_, c := claims(t, h.do(req{query: q("repository:alice/app:pull"), user: alice.Npub, pw: loginPW(alice, 30*time.Minute)}))
	if len(granted(c)) != 0 {
		t.Fatal("stale view still granted member access (denyMembers)")
	}
	_, c = claims(t, h.do(req{query: q("repository:bodies/x:pull"), user: builder.Npub, pw: loginPW(builder, 30*time.Minute)}))
	if len(granted(c)) != 1 {
		t.Fatal("identities grants must keep working when stale")
	}
	_, c = claims(t, h.do(req{query: q("repository:x/y:pull"), user: "node-pull", pw: "pull-secret"}))
	if len(granted(c)) != 1 {
		t.Fatal("static users must keep working when stale")
	}
	ready := httptest.NewRecorder()
	h.h.ServeHTTP(ready, httptest.NewRequest("GET", "/readyz", nil))
	if ready.Code != 200 {
		t.Fatal("readyz must not depend on membership freshness")
	}

	all := newHarness(t, func(c *config.Config) { c.Membership.OnStale = "denyAll" }, "")
	stale(all)
	if w := all.do(req{query: q(), user: alice.Npub, pw: loginPW(alice, 30*time.Minute)}); w.Code != 503 {
		t.Fatalf("denyAll: %d", w.Code)
	}
	if w := all.do(req{query: q(), user: "node-pull", pw: "pull-secret"}); w.Code != 200 {
		t.Fatalf("denyAll must not affect static users: %d", w.Code)
	}

	keep := newHarness(t, func(c *config.Config) { c.Membership.OnStale = "keepLastView" }, "")
	stale(keep)
	_, c = claims(t, keep.do(req{query: q("repository:alice/app:pull"), user: alice.Npub, pw: loginPW(alice, 30*time.Minute)}))
	if len(granted(c)) != 1 {
		t.Fatal("keepLastView")
	}
}

func TestRevocationTakesEffectAtNextToken(t *testing.T) {
	h := newHarness(t, nil, "")
	pw := loginPW(alice, 30*time.Minute)
	_, c := claims(t, h.do(req{query: q("repository:alice/app:push"), user: alice.Npub, pw: pw}))
	if len(granted(c)) != 1 {
		t.Fatal("before revocation")
	}
	h.store.Ingest(authority.Member(30078, "member:", "alice", alice.Pub, "dead", time.Now()))
	// Same (cached) login event: the cache holds the signature check only.
	_, c = claims(t, h.do(req{query: q("repository:alice/app:push"), user: alice.Npub, pw: pw}))
	if len(granted(c)) != 0 {
		t.Fatal("revoked member still granted")
	}
}

func TestRequireTLS(t *testing.T) {
	h := newHarness(t, nil, "")
	pw := loginPW(alice, 30*time.Minute)
	if w := h.do(req{query: q(), user: alice.Npub, pw: pw, remote: "203.0.113.9:5555"}); w.Code != 403 {
		t.Fatalf("plain HTTP from the internet: %d", w.Code)
	}
	spoof := map[string]string{"X-Forwarded-Proto": "https"}
	if w := h.do(req{query: q(), user: alice.Npub, pw: pw, remote: "203.0.113.9:5555", headers: spoof}); w.Code != 403 {
		t.Fatalf("X-Forwarded-Proto from an untrusted peer was believed: %d", w.Code)
	}
	if w := h.do(req{query: q(), user: alice.Npub, pw: pw, headers: map[string]string{"X-Forwarded-Proto": "http"}}); w.Code != 403 {
		t.Fatalf("proxy said http: %d", w.Code)
	}
	if w := h.do(req{query: q(), user: alice.Npub, pw: pw}); w.Code != 200 {
		t.Fatalf("https via trusted proxy: %d", w.Code)
	}
	off := newHarness(t, func(c *config.Config) { c.Server.RequireTLS = false }, "")
	if w := off.do(req{query: q(), user: alice.Npub, pw: pw, remote: "203.0.113.9:5555"}); w.Code != 200 {
		t.Fatalf("requireTLS false: %d", w.Code)
	}
}

func rateLimited(c *config.Config) {
	c.RateLimit.Enabled = true
	c.RateLimit.Burst = 3
	c.RateLimit.PerIP = config.Rate{N: 1, Per: time.Hour}
	c.RateLimit.PerPubkey = config.Rate{N: 1, Per: time.Hour}
	c.RateLimit.PerStaticUser = config.Rate{N: 1, Per: time.Hour}
	c.RateLimit.FailuresPerIP = config.Rate{N: 1, Per: time.Hour}
}

func fromIP(ip string) map[string]string {
	return map[string]string{"X-Forwarded-For": ip, "X-Forwarded-Proto": "https"}
}

func TestPerIPLimitCannotBeDodgedWithForwardedFor(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		rateLimited(c)
		c.Server.RequireTLS = false
		c.RateLimit.FailuresPerIP = config.Rate{}
	}, "")
	codes := []int{}
	for i := range 5 {
		// An attacker connecting directly rotates X-Forwarded-For.
		w := h.do(req{query: q(), user: "node-pull", pw: "pull-secret", remote: "198.51.100.1:1",
			headers: map[string]string{"X-Forwarded-For": fmt.Sprintf("192.0.2.%d", i)}})
		codes = append(codes, w.Code)
	}
	if codes[3] != 429 || codes[4] != 429 {
		t.Fatalf("spoofed X-Forwarded-For dodged the IP limit: %v", codes)
	}
}

func TestForgedRequestsCannotLockOutAPubkey(t *testing.T) {
	h := newHarness(t, rateLimited, "")
	forged := alice.LoginEvent(realm, time.Now(), 30*time.Minute)
	forged.Sig = strings.Repeat("0", 128)
	for range 10 {
		h.do(req{query: q(), user: alice.Npub, pw: testkit.Password(forged), headers: fromIP("198.51.100.66")})
	}
	// The attacker's IP is now limited...
	if w := h.do(req{query: q(), user: alice.Npub, pw: loginPW(alice, 30*time.Minute), headers: fromIP("198.51.100.66")}); w.Code != 429 {
		t.Fatalf("failures from one IP not limited: %d", w.Code)
	}
	// ...but alice, from her own address, is not locked out.
	if w := h.do(req{query: q(), user: alice.Npub, pw: loginPW(alice, 30*time.Minute), headers: fromIP("203.0.113.20")}); w.Code != 200 {
		t.Fatalf("forged requests locked alice out: %d %s", w.Code, w.Body)
	}
}

func TestPerPubkeyAndStaticLimits(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { rateLimited(c); c.RateLimit.PerIP = config.Rate{} }, "")
	var last int
	for i := range 5 {
		last = h.do(req{query: q(), user: alice.Npub, pw: loginPW(alice, 30*time.Minute), headers: fromIP(fmt.Sprintf("203.0.113.%d", i))}).Code
	}
	if last != 429 {
		t.Fatalf("per-pubkey limit not applied across IPs: %d", last)
	}
	for i := range 5 {
		last = h.do(req{query: q(), user: "node-pull", pw: "pull-secret", headers: fromIP(fmt.Sprintf("203.0.113.%d", 100+i))}).Code
	}
	if last != 429 {
		t.Fatalf("per-static-user limit: %d", last)
	}
}

func TestLogsNeverContainSecrets(t *testing.T) {
	h := newHarness(t, nil, "")
	ev := alice.LoginEvent(realm, time.Now(), 30*time.Minute)
	pw := testkit.Password(ev)
	w := h.do(req{query: q("repository:alice/app:pull"), user: alice.Npub, pw: pw})
	b, _ := claims(t, w)
	h.do(req{query: q(), user: alice.Npub, pw: pw + "x"})
	h.do(req{query: q(), user: "node-pull", pw: "pull-secret"})
	h.do(req{query: q(), user: "node-pull", pw: "wrong-secret"})
	logs := h.logs.String()
	for name, secret := range map[string]string{
		"password": pw, "signature": ev.Sig, "token": b.Token, "static password": "pull-secret", "wrong password": "wrong-secret",
		"token signature": strings.Split(b.Token, ".")[2],
	} {
		if strings.Contains(logs, secret) {
			t.Errorf("logs contain the %s", name)
		}
	}
	for _, want := range []string{alice.Pub, `"result":"granted"`, `"reason":"bad_password"`, "repository:alice/app:pull"} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs missing %q", want)
		}
	}
	quiet := newHarness(t, func(c *config.Config) { c.Logging.LogGranted = false }, "")
	quiet.do(req{query: q(), user: alice.Npub, pw: pw})
	if strings.Contains(quiet.logs.String(), "granted") {
		t.Fatal("logGranted false still logged a grant")
	}
}

func TestAdminEndpoints(t *testing.T) {
	h := newHarness(t, nil, "")
	h.do(req{query: q(), user: alice.Npub, pw: "bad"})
	for path, want := range map[string]string{"/healthz": "ok", "/readyz": "ready", "/metrics": "registry_pass_logins_total"} {
		w := httptest.NewRecorder()
		h.h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 || !strings.Contains(w.Body.String(), want) {
			t.Errorf("%s: %d %s", path, w.Code, w.Body.String()[:min(80, w.Body.Len())])
		}
	}
	w := httptest.NewRecorder()
	h.h.ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	for _, m := range []string{"registry_pass_membership_members 1", "registry_pass_membership_fresh 1", "registry_pass_certificate_expiry_seconds", "registry_pass_membership_source_sync_age_seconds"} {
		if !strings.Contains(w.Body.String(), m) {
			t.Errorf("metrics missing %s", m)
		}
	}

	sep := newHarness(t, func(c *config.Config) { c.Admin.Listen = "127.0.0.1:0" }, "")
	w = httptest.NewRecorder()
	sep.h.ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if w.Code == 200 {
		t.Fatal("metrics exposed on the public listener though admin has its own")
	}
	w = httptest.NewRecorder()
	sep.srv.AdminHandler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if w.Code != 200 {
		t.Fatal("admin handler")
	}
}

func TestRunServesTLSAndShutsDown(t *testing.T) {
	dir := t.TempDir()
	keyPEM, certPEM, _ := token.Generate("ES256", "127.0.0.1", time.Hour)
	os.WriteFile(filepath.Join(dir, "k"), keyPEM, 0o600)
	os.WriteFile(filepath.Join(dir, "c"), certPEM, 0o600)
	h := newHarness(t, func(c *config.Config) {
		c.Server.TLS = config.TLS{CertFile: filepath.Join(dir, "c"), KeyFile: filepath.Join(dir, "k"), MinVersion: "1.2"}
		c.Admin.Listen = "127.0.0.1:0"
		c.Server.MaxHeaderBytes = 4096
	}, "")
	main, _ := net.Listen("tcp", "127.0.0.1:0")
	admin, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.srv.Run(ctx, Listeners{Main: main, Admin: admin}) }()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: insecureTLS()}, Timeout: 5 * time.Second}
	resp, err := client.Get("https://" + main.Addr().String() + "/token?service=" + service)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("TLS request: %d", resp.StatusCode)
	}
	// An oversized header is refused before it reaches the handler.
	r, _ := http.NewRequest("GET", "https://"+main.Addr().String()+"/token", nil)
	r.Header.Set("Authorization", "Basic "+strings.Repeat("A", 8192))
	if resp, err := client.Do(r); err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
			t.Fatalf("oversized header: %d", resp.StatusCode)
		}
	}
	resp, err = http.Get("http://" + admin.Addr().String() + "/healthz")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("admin listener: %v", err)
	}
	resp.Body.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}

func TestListen(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Server.Listen = "127.0.0.1:0"; c.Admin.Listen = "127.0.0.1:0" }, "")
	l, err := h.srv.Listen()
	if err != nil {
		t.Fatal(err)
	}
	l.Main.Close()
	l.Admin.Close()
	bad := newHarness(t, func(c *config.Config) { c.Server.Listen = "256.0.0.1:1" }, "")
	if _, err := bad.srv.Listen(); err == nil {
		t.Fatal("bad listen address accepted")
	}
	if _, err := New(Deps{}); err == nil {
		t.Fatal("New without deps")
	}
}

func TestClientIP(t *testing.T) {
	p := proxies{}
	for _, c := range []string{"10.0.0.0/8", "192.168.1.1"} {
		n, _ := config.ParseCIDR(c)
		p = append(p, n)
	}
	cases := []struct {
		remote, xff, want string
	}{
		{"203.0.113.1:1", "1.2.3.4", "203.0.113.1"},         // untrusted peer: header ignored
		{"10.0.0.1:1", "1.2.3.4", "1.2.3.4"},                // trusted proxy
		{"10.0.0.1:1", "6.6.6.6, 1.2.3.4", "1.2.3.4"},       // spoofed left entry ignored
		{"10.0.0.1:1", "1.2.3.4, 10.0.0.2", "1.2.3.4"},      // chain of trusted proxies
		{"10.0.0.1:1", "", "10.0.0.1"},                      // no header
		{"10.0.0.1:1", "garbage", "10.0.0.1"},               // unparsable
		{"10.0.0.1:1", "10.0.0.3, 192.168.1.1", "10.0.0.1"}, // all trusted
		{"[2001:db8::1]:1", "1.2.3.4", "2001:db8::1"},       // IPv6 untrusted peer
		{"bogus", "", "bogus"},                              // unparsable remote
	}
	for _, tc := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tc.remote
		if tc.xff != "" {
			r.Header.Set("X-Forwarded-For", tc.xff)
		}
		if got := p.clientIP(r); got != tc.want {
			t.Errorf("remote %s xff %q: %s, want %s", tc.remote, tc.xff, got, tc.want)
		}
	}
}

func TestLimiterBoundsMemory(t *testing.T) {
	l := newLimiter(1, 1, 3)
	for i := range 10 {
		l.allow(fmt.Sprint(i))
	}
	if len(l.buckets) > 3 {
		t.Fatalf("limiter grew to %d keys", len(l.buckets))
	}
	if newLimiter(0, 1, 1) != nil || !(*limiter)(nil).allow("x") || !(*limiter)(nil).peek("x") {
		t.Fatal("nil limiter must allow")
	}
}

// insecureTLS accepts the test's self-signed certificate.
func insecureTLS() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }
