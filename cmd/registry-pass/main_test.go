package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/registry-pass/internal/testkit"
)

var (
	authority = testkit.NewKey("authority")
	alice     = testkit.NewKey("alice")
)

func runCmd(t *testing.T, ctx context.Context, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(ctx, args, nil, &out, &errOut)
	return code, out.String(), errOut.String()
}

func freePort(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

type setup struct {
	dir, config, grants, members, listen, admin string
}

func newSetup(t *testing.T, reload string) setup {
	t.Helper()
	dir := t.TempDir()
	s := setup{dir: dir, config: filepath.Join(dir, "config.yaml"), grants: filepath.Join(dir, "grants.yaml"),
		members: filepath.Join(dir, "members.jsonl"), listen: freePort(t), admin: freePort(t)}
	if code, _, e := runCmd(t, context.Background(), "keygen", "--key-out", filepath.Join(dir, "pass.key"), "--cert-out", filepath.Join(dir, "pass.crt")); code != 0 {
		t.Fatalf("keygen: %s", e)
	}
	os.WriteFile(s.grants, []byte(`templates: [{repos: "{name}/**", actions: [pull, push]}]`), 0o600)
	ev := authority.Member(30078, "member:", "alice", alice.Pub, "alive", time.Now().Add(-time.Minute))
	data, _ := json.Marshal(ev)
	os.WriteFile(s.members, append(data, '\n'), 0o600)
	os.WriteFile(s.config, []byte(fmt.Sprintf(`
realm: http://%s/token
services: [registry.example]
server: {listen: %q, requireTLS: false}
admin: {listen: %q}
token: {signingKeyFile: %s, certificateFile: %s}
membership:
  authorities: [%s]
  sources: [{file: {path: %s}}]
grants: {file: %s, reload: %s}
logging: {level: debug}
`, s.listen, s.listen, s.admin, filepath.Join(dir, "pass.key"), filepath.Join(dir, "pass.crt"), authority.Npub, s.members, s.grants, reload)), 0o600)
	return s
}

func TestVersionHelpAndUnknown(t *testing.T) {
	if code, out, _ := runCmd(t, context.Background(), "version"); code != 0 || strings.TrimSpace(out) != "dev" {
		t.Fatal("version")
	}
	if code, out, _ := runCmd(t, context.Background(), "help"); code != 0 || !strings.Contains(out, "config check") {
		t.Fatal("help")
	}
	if code, _, _ := runCmd(t, context.Background(), "frobnicate"); code != 2 {
		t.Fatal("unknown command")
	}
	if code, _, _ := runCmd(t, context.Background(), "--nope"); code != 2 {
		t.Fatal("unknown flag")
	}
	if code, _, _ := runCmd(t, context.Background(), "config"); code != 2 {
		t.Fatal("config without subcommand")
	}
	if defaultConfigPath([]string{"REGISTRY_PASS_CONFIG=/x.yaml"}) != "/x.yaml" || defaultConfigPath(nil) != "/etc/registry-pass/config.yaml" {
		t.Fatal("defaultConfigPath")
	}
	if got := withoutConfigVar([]string{"REGISTRY_PASS_CONFIG=/x", "A=1"}); len(got) != 1 {
		t.Fatal("withoutConfigVar")
	}
}

func TestKeygen(t *testing.T) {
	dir := t.TempDir()
	key, cert := filepath.Join(dir, "sub", "k.pem"), filepath.Join(dir, "sub", "c.pem")
	if code, _, e := runCmd(t, context.Background(), "keygen", "--alg", "ES384", "--key-out", key, "--cert-out", cert); code != 0 {
		t.Fatal(e)
	}
	st, _ := os.Stat(key)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v", st.Mode().Perm())
	}
	if code, _, _ := runCmd(t, context.Background(), "keygen", "--key-out", key, "--cert-out", cert); code != 1 {
		t.Fatal("keygen overwrote an existing key without --force")
	}
	if code, _, _ := runCmd(t, context.Background(), "keygen", "--force", "--key-out", key, "--cert-out", cert); code != 0 {
		t.Fatal("--force")
	}
	for _, args := range [][]string{{"--alg", "HS256"}, {"--days", "0"}, {"--bogus"}} {
		if code, _, _ := runCmd(t, context.Background(), append([]string{"keygen", "--key-out", filepath.Join(dir, "x"), "--cert-out", filepath.Join(dir, "y")}, args...)...); code == 0 {
			t.Errorf("keygen %v accepted", args)
		}
	}
}

func TestConfigCommands(t *testing.T) {
	s := newSetup(t, "none")
	if code, out, e := runCmd(t, context.Background(), "--config", s.config, "config", "check"); code != 0 || !strings.Contains(out, "OK") {
		t.Fatalf("check: %s", e)
	}
	if code, out, _ := runCmd(t, context.Background(), "--config", s.config, "config", "print"); code != 0 || !strings.Contains(out, "# file") {
		t.Fatalf("print: %s", out)
	}
	if code, out, _ := runCmd(t, context.Background(), "config", "env"); code != 0 || !strings.Contains(out, "REGISTRY_PASS_LOGIN__MAX_LIFETIME") {
		t.Fatal("env")
	}
	if code, _, _ := runCmd(t, context.Background(), "--config", s.config, "config", "bogus"); code != 2 {
		t.Fatal("bogus subcommand")
	}

	os.WriteFile(s.grants, []byte("templates: [{repos: \"x\", actions: [pull]}]"), 0o600)
	if code, _, e := runCmd(t, context.Background(), "--config", s.config, "config", "check"); code != 1 || !strings.Contains(e, "{name}") {
		t.Fatalf("invalid grants passed check: %s", e)
	}
	os.WriteFile(filepath.Join(s.dir, "pass.crt"), []byte("garbage"), 0o600)
	if code, _, _ := runCmd(t, context.Background(), "--config", s.config, "config", "check"); code != 1 {
		t.Fatal("bad certificate passed check")
	}
	os.Remove(s.members)
	if code, _, e := runCmd(t, context.Background(), "--config", s.config, "config", "check"); code != 1 || !strings.Contains(e, "file.path") {
		t.Fatalf("missing members file passed check: %s", e)
	}
	if code, _, _ := runCmd(t, context.Background(), "--config", filepath.Join(s.dir, "none.yaml"), "config", "print"); code != 1 {
		t.Fatal("missing config")
	}
}

func requestToken(t *testing.T, s setup, scope string, k testkit.Key) []string {
	t.Helper()
	q := url.Values{"service": {"registry.example"}, "scope": {scope}}
	req, _ := http.NewRequest("GET", "http://"+s.listen+"/token?"+q.Encode(), nil)
	ev := k.LoginEvent("http://"+s.listen+"/token", time.Now(), 30*time.Minute)
	req.SetBasicAuth(k.Npub, testkit.Password(ev))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("token: %d", resp.StatusCode)
	}
	var body struct{ Token string }
	json.NewDecoder(resp.Body).Decode(&body)
	payload, _ := base64.RawURLEncoding.DecodeString(strings.Split(body.Token, ".")[1])
	var c struct {
		Access []struct{ Name string }
	}
	json.Unmarshal(payload, &c)
	var names []string
	for _, a := range c.Access {
		names = append(names, a.Name)
	}
	return names
}

func TestServeEndToEndWithGrantsReload(t *testing.T) {
	s := newSetup(t, "watch")
	ctx, cancel := context.WithCancel(context.Background())
	var errOut bytes.Buffer
	done := make(chan int, 1)
	go func() { done <- run(ctx, []string{"--config", s.config}, nil, &bytes.Buffer{}, &errOut) }()

	waitHTTP(t, "http://"+s.admin+"/readyz")
	if got := requestToken(t, s, "repository:alice/app:pull,push", alice); len(got) != 1 {
		t.Fatalf("member access %v", got)
	}
	resp, err := http.Get("http://" + s.listen + "/metrics")
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode == 200 {
			t.Fatal("metrics on the public listener")
		}
	}

	// Revoke the template by editing the grants file: watch mode reloads it.
	os.WriteFile(s.grants, []byte("templates: []\n"), 0o600)
	deadline := time.Now().Add(10 * time.Second)
	for len(requestToken(t, s, "repository:alice/app:pull", alice)) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("grants change not picked up")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// A broken grants file is refused and the previous grants stay.
	os.WriteFile(s.grants, []byte("templates: [ {"), 0o600)
	time.Sleep(300 * time.Millisecond)
	if got := requestToken(t, s, "repository:alice/app:pull", alice); len(got) != 0 {
		t.Fatalf("broken grants changed access: %v", got)
	}

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("serve exit %d: %s", code, errOut.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("serve did not stop")
	}
	logs := errOut.String()
	if !strings.Contains(logs, "grants reloaded") || !strings.Contains(logs, "grants reload failed") {
		t.Fatalf("reload not logged:\n%s", logs)
	}
}

func TestServeFailures(t *testing.T) {
	if code, _, _ := runCmd(t, context.Background(), "--config", filepath.Join(t.TempDir(), "none.yaml")); code != 1 {
		t.Fatal("missing config")
	}
	s := newSetup(t, "none")
	os.Remove(filepath.Join(s.dir, "pass.key"))
	if code, _, _ := runCmd(t, context.Background(), "--config", s.config); code != 1 {
		t.Fatal("missing key")
	}
	s = newSetup(t, "none")
	l, _ := net.Listen("tcp", s.listen)
	defer l.Close()
	if code, _, _ := runCmd(t, context.Background(), "--config", s.config); code != 1 {
		t.Fatal("busy port")
	}
}

func waitHTTP(t *testing.T, u string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(u); err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return
			}
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatalf("%s not ready", u)
}
