package helper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/registry-pass/internal/login"
	"github.com/ohstr/registry-pass/internal/testkit"
)

const realm = "https://pass.example/token"

var alice = testkit.NewKey("alice")

func keyFile(t *testing.T, content string, mode os.FileMode) string {
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	os.Chmod(p, mode)
	return p
}

func newHelper(t *testing.T, signer string, clock *time.Time) *Helper {
	return &Helper{
		Config: &Config{CacheDir: filepath.Join(t.TempDir(), "cache"), Registries: map[string]Registry{
			"registry.example": {Realm: realm, Service: "registry.example", Signer: signer, Lifetime: time.Hour, RefreshAt: 0.5, SignerTimeout: 5 * time.Second},
		}},
		Now: func() time.Time { return *clock },
	}
}

func verify(t *testing.T, c Credentials, at time.Time) login.Identity {
	t.Helper()
	v, err := login.New(login.Options{Realm: realm, Kind: 27235, MaxLifetime: time.Hour, MinRemaining: 2 * time.Minute,
		ClockSkew: 30 * time.Second, Now: func() time.Time { return at }})
	if err != nil {
		t.Fatal(err)
	}
	id, err := v.Verify(c.Username, c.Secret, "registry.example")
	if err != nil {
		t.Fatalf("server refused the helper's login: %v", err)
	}
	return id
}

func TestGetSignsALoginTheServerAccepts(t *testing.T) {
	clock := time.Now()
	for _, material := range []string{alice.Nsec, alice.Priv + "\n"} {
		h := newHelper(t, "file://"+keyFile(t, material, 0o600), &clock)
		c, err := h.Get(context.Background(), "https://registry.example/v2/")
		if err != nil {
			t.Fatal(err)
		}
		if c.Username != alice.Npub {
			t.Fatalf("username %s", c.Username)
		}
		if id := verify(t, c, clock); id.Pubkey != alice.Pub {
			t.Fatal("wrong identity")
		}
	}
}

func TestCacheReuseAndRefresh(t *testing.T) {
	clock := time.Now()
	h := newHelper(t, "file://"+keyFile(t, alice.Nsec, 0o600), &clock)
	first, err := h.Get(context.Background(), "registry.example")
	if err != nil {
		t.Fatal(err)
	}
	matches, _ := filepath.Glob(filepath.Join(h.Config.CacheDir, "*.json"))
	if len(matches) != 1 {
		t.Fatal("no cache file")
	}
	st, _ := os.Stat(matches[0])
	dst, _ := os.Stat(h.Config.CacheDir)
	if st.Mode().Perm() != 0o600 || dst.Mode().Perm() != 0o700 {
		t.Fatalf("cache modes %v %v", st.Mode().Perm(), dst.Mode().Perm())
	}

	clock = clock.Add(20 * time.Minute) // 40 min left: more than half
	again, _ := h.Get(context.Background(), "registry.example:443")
	if again.Secret != first.Secret {
		t.Fatal("cache not reused while more than refreshAt of the lifetime remains")
	}
	clock = clock.Add(15 * time.Minute) // 25 min left: less than half
	fresh, _ := h.Get(context.Background(), "registry.example")
	if fresh.Secret == first.Secret {
		t.Fatal("event not refreshed")
	}
	verify(t, fresh, clock)

	// A cache file others can read (or a symlink) is ignored.
	os.Chmod(matches[0], 0o644)
	clock = clock.Add(time.Second)
	if c, _ := h.Get(context.Background(), "registry.example"); c.Secret == fresh.Secret {
		t.Fatal("world-readable cache trusted")
	}
	evil := filepath.Join(t.TempDir(), "evil.json")
	data, _ := json.Marshal(cached{Username: "npub1evil", Secret: "x", Expires: clock.Add(time.Hour), Realm: realm})
	os.WriteFile(evil, data, 0o600)
	os.Remove(matches[0])
	os.Symlink(evil, matches[0])
	if c, _ := h.Get(context.Background(), "registry.example"); c.Username == "npub1evil" {
		t.Fatal("symlinked cache trusted")
	}
}

func TestCacheKeyedByRealm(t *testing.T) {
	clock := time.Now()
	h := newHelper(t, "file://"+keyFile(t, alice.Nsec, 0o600), &clock)
	first, _ := h.Get(context.Background(), "registry.example")
	r := h.Config.Registries["registry.example"]
	r.Realm = "https://other.example/token"
	h.Config.Registries["registry.example"] = r
	second, _ := h.Get(context.Background(), "registry.example")
	if first.Secret == second.Secret {
		t.Fatal("a login for one realm reused for another")
	}
}

func TestSignerErrors(t *testing.T) {
	clock := time.Now()
	cases := map[string]string{
		"world-readable key": "file://" + keyFile(t, alice.Nsec, 0o644),
		"missing key":        "file:///nonexistent/key",
		"npub as key":        "file://" + keyFile(t, alice.Npub, 0o600),
		"empty env":          "env:REGISTRY_PASS_TEST_UNSET",
		"unsupported":        "https://signer.example?secret=hunter2",
		"no socket":          "bunker+unix:///nonexistent/s.sock",
	}
	for name, uri := range cases {
		h := newHelper(t, uri, &clock)
		_, err := h.Get(context.Background(), "registry.example")
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%s: error leaks the URI's secret", name)
		}
	}
	t.Setenv("REGISTRY_PASS_TEST_NSEC", alice.Nsec)
	h := newHelper(t, "env:REGISTRY_PASS_TEST_NSEC", &clock)
	c, err := h.Get(context.Background(), "registry.example")
	if err != nil {
		t.Fatal(err)
	}
	verify(t, c, clock)
	t.Setenv("REGISTRY_PASS_TEST_BAD", "nope")
	if _, err := newHelper(t, "env:REGISTRY_PASS_TEST_BAD", &clock).Get(context.Background(), "registry.example"); err == nil {
		t.Fatal("bad env key accepted")
	}
}

func TestSocketSigner(t *testing.T) {
	clock := time.Now()
	uri := testkit.StartSocketSigner(t, alice)
	c, err := newHelper(t, uri, &clock).Get(context.Background(), "registry.example")
	if err != nil {
		t.Fatal(err)
	}
	verify(t, c, clock)
}

type badSigner struct{}

func (badSigner) PubKey() string { return alice.Pub }
func (badSigner) Sign(_ context.Context, ev *nip01.Event) error {
	ev.ID = strings.Repeat("0", 64)
	ev.Sig = strings.Repeat("0", 128)
	return nil
}

type failingSigner struct{}

func (failingSigner) PubKey() string                           { return alice.Pub }
func (failingSigner) Sign(context.Context, *nip01.Event) error { return errors.New("user rejected") }

func TestUntrustworthySigner(t *testing.T) {
	clock := time.Now()
	for name, s := range map[string]Signer{"forged signature": badSigner{}, "refused": failingSigner{}} {
		h := newHelper(t, "file:///unused", &clock)
		h.OpenSigner = func(context.Context, string, string, time.Duration) (Signer, func(), error) { return s, func() {}, nil }
		if _, err := h.Get(context.Background(), "registry.example"); err == nil {
			t.Errorf("%s: helper returned credentials", name)
		}
	}
}

func TestProtocol(t *testing.T) {
	clock := time.Now()
	h := newHelper(t, "file://"+keyFile(t, alice.Nsec, 0o600), &clock)
	run := func(action, in string) (int, string) {
		var out, errOut bytes.Buffer
		code := h.Run(context.Background(), action, strings.NewReader(in), &out, &errOut, "v1")
		return code, out.String() + errOut.String()
	}
	code, out := run("get", "registry.example\n")
	var c Credentials
	if code != 0 || json.Unmarshal([]byte(out), &c) != nil || c.Username != alice.Npub || c.ServerURL != "registry.example" {
		t.Fatalf("get: %d %s", code, out)
	}
	if code, out := run("get", "unknown.example\n"); code != 1 || strings.TrimSpace(out) != ErrNotFound.Error() {
		t.Fatalf("unknown registry: %d %q", code, out)
	}
	if code, _ := run("get", ""); code != 1 {
		t.Fatal("get without input")
	}
	if code, _ := run("store", `{"ServerURL":"x","Username":"u","Secret":"s"}`); code != 0 {
		t.Fatal("store must be a no-op success")
	}
	if code, _ := run("erase", "registry.example\n"); code != 0 {
		t.Fatal("erase must be a no-op success")
	}
	if code, out := run("list", ""); code != 0 || strings.TrimSpace(out) != "{}" {
		t.Fatalf("list: %s", out)
	}
	if code, out := run("version", ""); code != 0 || strings.TrimSpace(out) != "v1" {
		t.Fatal("version")
	}
	if code, _ := run("bogus", ""); code != 2 {
		t.Fatal("unknown action")
	}
}

func TestNormalizeHost(t *testing.T) {
	for in, want := range map[string]string{
		"registry.example":                 "registry.example",
		"https://Registry.Example/v2/":     "registry.example",
		"registry.example:443":             "registry.example",
		"registry.example:5000":            "registry.example:5000",
		"http://localhost:80":              "localhost",
		"https://[::1]:5000":               "[::1]:5000",
		"  registry.example  ":             "registry.example",
		"https://user:pw@registry.example": "registry.example",
	} {
		if got := NormalizeHost(in); got != want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLoadConfig(t *testing.T) {
	write := func(body string) string {
		p := filepath.Join(t.TempDir(), "helper.yaml")
		os.WriteFile(p, []byte(body), 0o600)
		return p
	}
	c, err := LoadConfig(write("registries:\n  Registry.Example:443:\n    realm: " + realm + "\n    signer: env:X\n"))
	if err != nil {
		t.Fatal(err)
	}
	r, ok := c.Registries["registry.example"]
	if !ok || r.Lifetime != time.Hour || r.RefreshAt != 0.5 || r.SignerTimeout != time.Minute {
		t.Fatalf("defaults/normalization: %+v", c.Registries)
	}
	for name, body := range map[string]string{
		"unknown key":   "registrys: {}",
		"no signer":     "registries:\n  r:\n    realm: " + realm + "\n",
		"bad refreshAt": "registries:\n  r:\n    realm: x\n    signer: env:X\n    refreshAt: 1.5\n",
		"short life":    "registries:\n  r:\n    realm: x\n    signer: env:X\n    lifetime: 1m\n",
	} {
		if _, err := LoadConfig(write(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "none")); err == nil {
		t.Fatal("missing file accepted")
	}
	if !strings.HasSuffix(DefaultConfigPath(), filepath.Join("registry-pass", "helper.yaml")) {
		t.Fatal("DefaultConfigPath")
	}
}

func TestBunkerSessionFiles(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "s.session")
	if _, ok := readSession(p); ok {
		t.Fatal("missing session read")
	}
	os.WriteFile(p, []byte(`{"client_key":"k","relays":["ws://x"]}`), 0o644)
	if _, ok := readSession(p); ok {
		t.Fatal("world-readable session trusted")
	}
	os.Chmod(p, 0o600)
	if s, ok := readSession(p); !ok || s.ClientKey != "k" {
		t.Fatal("session not read")
	}
	if _, _, err := OpenSigner(context.Background(), "bunker://"+alice.Pub+"?relay=ws://127.0.0.1:1", p, 300*time.Millisecond); err == nil {
		t.Fatal("unreachable bunker accepted")
	}
	if redactURI("bunker://x?secret=s") != "bunker://x?…" {
		t.Fatal("redactURI")
	}
}
