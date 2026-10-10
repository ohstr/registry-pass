package config

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/registry-pass/internal/testkit"
)

var authority = testkit.NewKey("authority")

var baseSections = []struct{ key, body string }{
	{"realm", "realm: https://pass.example/token\n"},
	{"services", "services: [registry.example]\n"},
	{"server", "server:\n  trustedProxies: [10.0.0.0/8]\n"},
	{"token", "token:\n  signingKeyFile: /run/secrets/pass.key\n  certificateFile: /run/secrets/pass.crt\n"},
	{"membership", "membership:\n  authorities: [" + authority.Npub + "]\n  sources:\n    - file: {path: /etc/registry-pass/members.jsonl}\n"},
}

// minimal writes a valid config; extra replaces whole top-level sections
// it names (server, token, membership) and adds any others.
func minimal(t *testing.T, extra string) string {
	t.Helper()
	var b strings.Builder
	for _, sec := range baseSections {
		if !strings.HasPrefix(extra, sec.key+":") && !strings.Contains(extra, "\n"+sec.key+":") {
			b.WriteString(sec.body)
		}
	}
	b.WriteString(extra)
	return write(t, b.String())
}

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func problems(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	return err.Error()
}

func TestMinimalConfigGetsDefaults(t *testing.T) {
	cfg, origins, err := Load(minimal(t, ""), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Login.MaxLifetime.D() != time.Hour || cfg.Token.Lifetime.D() != 5*time.Minute {
		t.Fatalf("defaults not applied: %+v %+v", cfg.Login, cfg.Token)
	}
	if got := cfg.Membership.Authorities[0]; got != authority.Pub {
		t.Fatalf("authority not normalized to hex: %s", got)
	}
	if cfg.Membership.Sources[0].File.PollInterval.D() != DefaultPollInterval {
		t.Fatal("source defaults not applied")
	}
	if origins.Of("realm") != FromFile || origins.Of("login.maxLifetime") != FromDefault {
		t.Fatalf("origins wrong: %v", origins)
	}
}

func TestEnvOverridesFileAndDefaults(t *testing.T) {
	p := minimal(t, "login:\n  maxLifetime: 30m\n")
	cfg, origins, err := Load(p, []string{
		"REGISTRY_PASS_LOGIN__MAX_LIFETIME=2h",
		"REGISTRY_PASS_RATE_LIMIT__PER_IP=50/s",
		"REGISTRY_PASS_SERVICES=a.example, b.example",
		"REGISTRY_PASS_GRANTS__STATIC_USER_CACHE_TTL=0s",
		"REGISTRY_PASS_TOKEN__X5C=false",
		"REGISTRY_PASS_LOGIN__CACHE_SIZE=5",
		"UNRELATED=1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Login.MaxLifetime.D() != 2*time.Hour {
		t.Fatalf("env must win over file, got %s", cfg.Login.MaxLifetime)
	}
	if cfg.RateLimit.PerIP.N != 50 || cfg.RateLimit.PerIP.Per != time.Second {
		t.Fatalf("rate: %+v", cfg.RateLimit.PerIP)
	}
	if strings.Join(cfg.Services, "|") != "a.example|b.example" {
		t.Fatalf("services: %v", cfg.Services)
	}
	if cfg.Token.X5C || cfg.Login.CacheSize != 5 || cfg.Grants.StaticUserCacheTTL != 0 {
		t.Fatal("bool/int/duration env not applied")
	}
	if origins.Of("login.maxLifetime") != FromEnv {
		t.Fatal("origin should be env")
	}
}

func TestUnknownEnvOverrideIsRejected(t *testing.T) {
	_, _, err := Load(minimal(t, ""), []string{"REGISTRY_PASS_LOGIN__MAX_LIFETIM=2h"})
	if !strings.Contains(problems(t, err), "unknown environment override") {
		t.Fatal(err)
	}
}

func TestBadEnvValues(t *testing.T) {
	for _, kv := range []string{
		"REGISTRY_PASS_LOGIN__MAX_LIFETIME=forever",
		"REGISTRY_PASS_TOKEN__X5C=maybe",
		"REGISTRY_PASS_LOGIN__CACHE_SIZE=lots",
		"REGISTRY_PASS_RATE_LIMIT__PER_IP=5/day",
		"REGISTRY_PASS_RATE_LIMIT__PER_IP=five/min",
		"REGISTRY_PASS_LOGIN__CLOCK_SKEW=-5s",
	} {
		if _, _, err := Load(minimal(t, ""), []string{kv}); err == nil {
			t.Errorf("%s: expected an error", kv)
		}
	}
}

func TestStrictYAML(t *testing.T) {
	cases := map[string]string{
		"unknown key":    minimal(t, "login:\n  maxLifetme: 1h\n"),
		"duplicate key":  minimal(t, "login:\n  kind: 1\nlogin:\n  kind: 2\n"),
		"two documents":  minimal(t, "---\nrealm: x\n"),
		"bad duration":   minimal(t, "login:\n  maxLifetime: soon\n"),
		"bad rate":       minimal(t, "rateLimit:\n  perIP: 300\n"),
		"wrong type":     minimal(t, "login:\n  kind: [1]\n"),
		"source twice":   write(t, strings.Replace(readFile(t, minimal(t, "")), "- file: {path: /etc/registry-pass/members.jsonl}", "- file: {path: /x}\n      http: {url: http://x}", 1)),
		"no source type": write(t, strings.Replace(readFile(t, minimal(t, "")), "- file: {path: /etc/registry-pass/members.jsonl}", "- {}", 1)),
	}
	for name, p := range cases {
		if _, _, err := Load(p, nil); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func readFile(t *testing.T, p string) string {
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestCrossChecks(t *testing.T) {
	cases := map[string]struct{ extra, want string }{
		"minLifetime below 60s":       {"token:\n  signingKeyFile: k\n  certificateFile: c\n  minLifetime: 30s\n", "token.minLifetime"},
		"lifetime below minLifetime":  {"token:\n  signingKeyFile: k\n  certificateFile: c\n  lifetime: 30s\n", "token.lifetime"},
		"minRemaining below minLife":  {"login:\n  minRemaining: 30s\n", "login.minRemaining"},
		"maxLifetime below remaining": {"login:\n  maxLifetime: 1m\n", "login.maxLifetime"},
		"staleAfter vs poll": {"membership:\n  authorities: [" + authority.Npub + "]\n  staleAfter: 1m\n  sources:\n    - file: {path: /x, watch: false, pollInterval: 5m}\n",
			"pollInterval"},
		"staleAfter vs resync":   {"membership:\n  authorities: [" + authority.Npub + "]\n  sources:\n    - relay: {urls: [wss://r.example], resync: 1h}\n", "resync"},
		"heartbeat under prefix": {"membership:\n  authorities: [" + authority.Npub + "]\n  heartbeat: {enabled: true, d: \"member:hb\"}\n  sources:\n    - file: {path: /x}\n", "heartbeat.d"},
		"reader both":            {"membership:\n  authorities: [" + authority.Npub + "]\n  sources:\n    - relay: {urls: [wss://r.example], reader: {keyFile: /k, signer: \"bunker://x\"}}\n", "exactly one of keyFile or signer"},
		"reader bad signer":      {"membership:\n  authorities: [" + authority.Npub + "]\n  sources:\n    - relay: {urls: [wss://r.example], reader: {signer: \"http://x\"}}\n", "bunker://"},
		"relay http url":         {"membership:\n  authorities: [" + authority.Npub + "]\n  sources:\n    - relay: {urls: [\"https://r.example\"]}\n", "ws://"},
		"not addressable":        {"membership:\n  authorities: [" + authority.Npub + "]\n  kind: 1\n  sources:\n    - file: {path: /x}\n", "addressable"},
		"x5c off kid none":       {"token:\n  signingKeyFile: k\n  certificateFile: c\n  x5c: false\n  kid: none\n", "kid must not be none"},
		"unanchored names":       {"grants:\n  namePattern: \"[a-z]+\"\n", "anchored"},
		"bad enum":               {"membership:\n  authorities: [" + authority.Npub + "]\n  onStale: shrug\n  sources:\n    - file: {path: /x}\n", "onStale"},
		"admin same port":        {"admin:\n  listen: \":5001\"\n", "admin.listen"},
		"admin path clash":       {"admin:\n  healthPath: /token\n", "collides"},
		"tls half":               {"server:\n  trustedProxies: [10.0.0.0/8]\n  tls: {certFile: /c}\n", "certFile and keyFile"},
		"bad proxy":              {"server:\n  trustedProxies: [\"not-an-ip\"]\n", "not an IP"},
		"tiny headers":           {"server:\n  trustedProxies: [10.0.0.0/8]\n  maxHeaderBytes: 100\n", "maxHeaderBytes"},
		"burst zero":             {"rateLimit:\n  burst: 0\n", "burst"},
	}
	for name, tc := range cases {
		_, _, err := Load(minimal(t, tc.extra), nil)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want error containing %q, got %v", name, tc.want, err)
		}
	}
}

func TestRequireTLS(t *testing.T) {
	p := write(t, `
realm: http://pass.example/token
services: [r]
token: {signingKeyFile: k, certificateFile: c}
membership: {enabled: false}
`)
	msg := problems(t, func() error { _, _, err := Load(p, nil); return err }())
	if !strings.Contains(msg, "realm: must be https") || !strings.Contains(msg, "server.requireTLS") {
		t.Fatalf("want both TLS problems, got %s", msg)
	}
	if _, _, err := Load(p, []string{"REGISTRY_PASS_SERVER__REQUIRE_TLS=false"}); err != nil {
		t.Fatalf("requireTLS=false should allow http: %v", err)
	}
}

func TestAuthoritiesRejectPrivateAndInvalidKeys(t *testing.T) {
	for _, bad := range []string{authority.Nsec, "abc", strings.Repeat("g", 64), strings.Repeat("0", 64)} {
		p := write(t, strings.Replace(readFile(t, minimal(t, "")), authority.Npub, bad, 1))
		if _, _, err := Load(p, nil); err == nil {
			t.Errorf("authority %q accepted", bad[:8])
		}
	}
	upper := strings.ToUpper(authority.Pub)
	p := write(t, strings.Replace(readFile(t, minimal(t, "")), authority.Npub, upper, 1))
	cfg, _, err := Load(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Membership.Authorities[0] != authority.Pub {
		t.Fatal("uppercase hex must normalize to lowercase")
	}
	dup := write(t, strings.Replace(readFile(t, minimal(t, "")), authority.Npub, authority.Npub+", "+authority.Pub, 1))
	if _, _, err := Load(dup, nil); err == nil || !strings.Contains(err.Error(), "duplicate authority") {
		t.Fatalf("npub and hex of one key must count as a duplicate: %v", err)
	}
}

func TestMembershipDisabledNeedsNoSources(t *testing.T) {
	p := write(t, `
realm: https://pass.example/token
services: [r]
server: {trustedProxies: [127.0.0.1]}
token: {signingKeyFile: k, certificateFile: c}
membership: {enabled: false}
`)
	if _, _, err := Load(p, nil); err != nil {
		t.Fatal(err)
	}
}

func TestInlineSecretHeadersRejected(t *testing.T) {
	extra := "membership:\n  authorities: [" + authority.Npub + "]\n  sources:\n    - http:\n        url: https://feed.example\n        headers: {Authorization: \"Bearer abc\"}\n"
	if _, _, err := Load(minimal(t, extra), nil); !errors.Is(unwrapValidation(err), ErrInlineSecret) && !strings.Contains(err.Error(), "{file:") {
		t.Fatalf("inline bearer token accepted: %v", err)
	}
	secret := filepath.Join(t.TempDir(), "token")
	os.WriteFile(secret, []byte("s3cr3t\n"), 0o600)
	extra = "membership:\n  authorities: [" + authority.Npub + "]\n  sources:\n    - http:\n        url: https://feed.example\n        headers: {Authorization: \"Bearer {file:" + secret + "}\"}\n"
	cfg, _, err := Load(minimal(t, extra), nil)
	if err != nil {
		t.Fatal(err)
	}
	v, _, err := ResolveFileRef(cfg.Membership.Sources[0].HTTP.Headers["Authorization"], true)
	if err != nil || v != "Bearer s3cr3t" {
		t.Fatalf("resolve: %q %v", v, err)
	}
	var buf bytes.Buffer
	if err := Print(&buf, cfg, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "s3cr3t") {
		t.Fatal("print leaked a secret")
	}
}

func unwrapValidation(err error) error {
	var ve *ValidationError
	if errors.As(err, &ve) {
		for _, p := range ve.Problems {
			if strings.Contains(p, ErrInlineSecret.Error()) {
				return ErrInlineSecret
			}
		}
	}
	return err
}

func TestPrintShowsOrigins(t *testing.T) {
	cfg, origins, err := Load(minimal(t, "login:\n  clockSkew: 10s\n"), []string{"REGISTRY_PASS_LOGIN__MAX_LIFETIME=2h"})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := Print(&buf, cfg, origins); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"maxLifetime: 2h0m0s # env", "clockSkew: 10s # file", "minRemaining: 2m0s # default"} {
		if !strings.Contains(out, want) {
			t.Errorf("print missing %q:\n%s", want, out)
		}
	}
}

func TestCheckFiles(t *testing.T) {
	cfg, _, err := Load(minimal(t, ""), nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := problems(t, cfg.CheckFiles())
	for _, want := range []string{"token.signingKeyFile", "grants.file", "file.path"} {
		if !strings.Contains(msg, want) {
			t.Errorf("CheckFiles missing %s: %s", want, msg)
		}
	}
}

func TestReadFileLimited(t *testing.T) {
	p := filepath.Join(t.TempDir(), "big")
	os.WriteFile(p, bytes.Repeat([]byte("a"), 100), 0o600)
	if _, err := ReadFileLimited(p, 10); err == nil {
		t.Fatal("oversized file accepted")
	}
	if d, err := ReadFileLimited(p, 100); err != nil || len(d) != 100 {
		t.Fatal(err)
	}
}

func TestUpperSnake(t *testing.T) {
	for in, want := range map[string]string{
		"maxLifetime": "MAX_LIFETIME", "perIP": "PER_IP", "requireTLS": "REQUIRE_TLS",
		"staticUserCacheTTL": "STATIC_USER_CACHE_TTL", "x5c": "X5C", "dPrefix": "D_PREFIX",
		"realm": "REALM", "certExpiryWarning": "CERT_EXPIRY_WARNING",
	} {
		if got := upperSnake(in); got != want {
			t.Errorf("upperSnake(%q) = %q, want %q", in, got, want)
		}
	}
	names := strings.Join(EnvNames(), " ")
	for _, want := range []string{"REGISTRY_PASS_LOGIN__MAX_LIFETIME", "REGISTRY_PASS_SERVER__TLS__CERT_FILE", "REGISTRY_PASS_RATE_LIMIT__PER_IP"} {
		if !strings.Contains(names, want) {
			t.Errorf("EnvNames missing %s", want)
		}
	}
	if strings.Contains(names, "SOURCES") {
		t.Error("sources must be file-only")
	}
}

func TestRateAndDuration(t *testing.T) {
	var r Rate
	for in, want := range map[string]Rate{"300/min": {300, time.Minute}, "5/s": {5, time.Second}, "10/hour": {10, time.Hour}, "0": {}} {
		if err := r.Set(in); err != nil || r != want {
			t.Errorf("Rate %q = %+v %v", in, r, err)
		}
	}
	if (Rate{N: 120, Per: time.Minute}).PerSecond() != 2 || (Rate{}).PerSecond() != 0 {
		t.Error("PerSecond")
	}
	if (Rate{N: 3, Per: time.Hour}).String() != "3/h" || (Rate{}).String() != "0" {
		t.Error("String")
	}
}
