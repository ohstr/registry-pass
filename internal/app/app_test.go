package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ohstr/registry-pass/internal/config"
	"github.com/ohstr/registry-pass/internal/membership"
	"github.com/ohstr/registry-pass/internal/testkit"
	"github.com/ohstr/registry-pass/internal/token"
)

var (
	authority = testkit.NewKey("authority")
	alice     = testkit.NewKey("alice")
)

func baseConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	keyPEM, certPEM, err := token.Generate("ES256", "t", 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "k"), keyPEM, 0o600)
	os.WriteFile(filepath.Join(dir, "c"), certPEM, 0o600)
	os.WriteFile(filepath.Join(dir, "g"), []byte(`templates: [{repos: "{name}/**", actions: [pull]}]`), 0o600)
	cfg := config.Default()
	cfg.Realm, cfg.Services = "https://pass.example/token", []string{"r"}
	cfg.Server.Listen = "127.0.0.1:0"
	cfg.Server.TrustedProxies = []string{"127.0.0.1"}
	cfg.Token.SigningKeyFile, cfg.Token.CertificateFile = filepath.Join(dir, "k"), filepath.Join(dir, "c")
	cfg.Grants.File = filepath.Join(dir, "g")
	cfg.Membership.Authorities = []string{authority.Pub}
	return &cfg
}

func TestBuildAllSourceTypes(t *testing.T) {
	var gotAuth atomic.Value
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("Authorization"))
		json.NewEncoder(w).Encode([]any{authority.Member(30078, "member:", "alice", alice.Pub, "alive", time.Now())})
	}))
	defer feed.Close()

	cfg := baseConfig(t)
	dir := t.TempDir()
	secret := filepath.Join(dir, "feed.token")
	os.WriteFile(secret, []byte("s3cret\n"), 0o600)
	readerKey := filepath.Join(dir, "reader")
	os.WriteFile(readerKey, []byte(testkit.NewKey("reader").Nsec), 0o600)
	members := filepath.Join(dir, "m.jsonl")
	os.WriteFile(members, nil, 0o600)
	relayURL := testkit.StartRelay(t, true)

	cfg.Membership.Sources = []config.Source{
		{HTTP: &config.HTTPSource{URL: feed.URL, Interval: config.Duration(time.Hour), Timeout: config.Duration(time.Second),
			Headers: map[string]string{"Authorization": "Bearer {file:" + secret + "}"}}},
		{File: &config.FileSource{Path: members, PollInterval: config.Duration(time.Hour)}},
		{Relay: &config.RelaySource{URLs: []string{relayURL}, Reader: &config.Reader{KeyFile: readerKey, SignerTimeout: config.Duration(time.Second)},
			AuthWait: config.Duration(time.Second), Resync: config.Duration(time.Hour), PageSize: 10, DedupeSize: 10}},
	}
	var logs bytes.Buffer
	a, err := Build(context.Background(), cfg, NewLogger(cfg.Logging, &logs))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Sources) != 3 {
		t.Fatalf("sources %d", len(a.Sources))
	}
	l, err := a.Server.Listen()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx, l) }()
	deadline := time.Now().Add(10 * time.Second)
	for a.Store.Lookup(alice.Pub).Name != "alice" {
		if time.Now().After(deadline) {
			t.Fatal("http feed not applied")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if gotAuth.Load() != "Bearer s3cret" {
		t.Fatalf("header from file not sent: %v", gotAuth.Load())
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), "s3cret") {
		t.Fatal("feed secret logged")
	}
}

func TestSIGHUPReload(t *testing.T) {
	// Own SIGHUP handler first, so the default action can never kill the
	// test process.
	guard := make(chan os.Signal, 1)
	signal.Notify(guard, syscall.SIGHUP)
	defer signal.Stop(guard)

	cfg := baseConfig(t)
	cfg.Membership.Enabled = false
	var logs safeBuffer
	a, err := Build(context.Background(), cfg, NewLogger(config.Logging{Level: "info", Format: "text"}, &logs))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.watchGrants(ctx)
	time.Sleep(100 * time.Millisecond)
	syscall.Kill(os.Getpid(), syscall.SIGHUP)
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(logs.String(), "grants reloaded") {
		if time.Now().After(deadline) {
			t.Fatal("SIGHUP did not reload grants")
		}
		time.Sleep(20 * time.Millisecond)
	}
	os.WriteFile(cfg.Grants.File, []byte("bogus: ["), 0o600)
	if err := a.ReloadGrants(); err == nil {
		t.Fatal("invalid grants accepted")
	}
}

func TestBuildFailures(t *testing.T) {
	cases := map[string]func(*config.Config){
		"missing key":    func(c *config.Config) { c.Token.SigningKeyFile = "/nonexistent" },
		"missing cert":   func(c *config.Config) { c.Token.CertificateFile = "/nonexistent" },
		"missing chain":  func(c *config.Config) { c.Token.ChainFile = "/nonexistent" },
		"missing grants": func(c *config.Config) { c.Grants.File = "/nonexistent" },
		"bad realm":      func(c *config.Config) { c.Realm = "::" },
		"bad reader key": func(c *config.Config) {
			p := filepath.Join(t.TempDir(), "rk")
			os.WriteFile(p, []byte("nope"), 0o600)
			c.Membership.Sources = []config.Source{{Relay: &config.RelaySource{URLs: []string{"ws://127.0.0.1:1"}, Reader: &config.Reader{KeyFile: p}}}}
		},
		"missing reader key": func(c *config.Config) {
			c.Membership.Sources = []config.Source{{Relay: &config.RelaySource{URLs: []string{"ws://127.0.0.1:1"}, Reader: &config.Reader{KeyFile: "/nonexistent"}}}}
		},
		"bad CA": func(c *config.Config) {
			c.Membership.Sources = []config.Source{{HTTP: &config.HTTPSource{URL: "https://x", CAFile: "/nonexistent"}}}
		},
		"empty source": func(c *config.Config) { c.Membership.Sources = []config.Source{{}} },
	}
	for name, mod := range cases {
		cfg := baseConfig(t)
		mod(cfg)
		if _, err := Build(context.Background(), cfg, NewLogger(cfg.Logging, &bytes.Buffer{})); err == nil {
			t.Errorf("%s: built", name)
		}
	}
}

func TestNewLoggerLevels(t *testing.T) {
	for _, lvl := range []string{"debug", "info", "warn", "error"} {
		var b bytes.Buffer
		NewLogger(config.Logging{Level: lvl, Format: "json"}, &b).Warn("x")
		if (lvl == "error") == strings.Contains(b.String(), `"msg":"x"`) {
			t.Errorf("level %s", lvl)
		}
	}
	var b bytes.Buffer
	NewLogger(config.Logging{Level: "info", Format: "text"}, &b).Info("hello")
	if !strings.Contains(b.String(), "msg=hello") {
		t.Fatal("text format")
	}
}

var _ membership.Source = (*membership.FileSource)(nil)

type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}
