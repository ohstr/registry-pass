// Package integration runs registry-pass against real Distribution
// registries and real clients.
package integration

import (
	"context"
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
	"testing"
	"time"

	"github.com/distribution/distribution/v3/configuration"
	"github.com/distribution/distribution/v3/registry/handlers"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/registry-pass/internal/app"
	"github.com/ohstr/registry-pass/internal/config"
	"github.com/ohstr/registry-pass/internal/testkit"
	"github.com/ohstr/registry-pass/internal/token"
	"golang.org/x/crypto/bcrypt"

	_ "github.com/distribution/distribution/v3/registry/auth/token"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/inmemory"
)

const service = "registry.test"

var (
	authority = testkit.NewKey("authority")
	alice     = testkit.NewKey("alice")
	bob       = testkit.NewKey("bob")
	builder   = testkit.NewKey("builder")
	mallory   = testkit.NewKey("mallory")
)

// pass is a running registry-pass.
type pass struct {
	t       *testing.T
	dir     string
	addr    string
	realm   string
	certPEM string // path
	keyPEM  string // path
	members string
	grants  string
	app     *app.App
}

type passOpts struct {
	grants   string
	members  []*nip01.Event
	relayURL string   // membership from a relay instead of the file
	extra    string   // appended to the config
	env      []string // environment overrides
	// realmHost replaces localhost in the realm and makes registry-pass
	// listen on every interface, for clients outside this network
	// namespace (the docker daemon).
	realmHost string
}

const defaultGrants = `
templates: [{repos: "{name}/**", actions: [pull, push]}]
anonymous: [{repos: "public/**", actions: [pull]}]
identities:
  %s: [{repos: "bodies/**", actions: [pull, push]}]
staticUsers:
  node-pull:
    bcrypt: %q
    grants: [{repos: "**", actions: [pull]}]
deny: [%s]
`

// staticPassword is node-pull's password in defaultGrants.
const staticPassword = "pull-secret"

var staticHash = func() string {
	h, err := bcrypt.GenerateFromPassword([]byte(staticPassword), 10)
	if err != nil {
		panic(err)
	}
	return string(h)
}()

func generate(t *testing.T) (keyPEM, certPEM []byte) {
	t.Helper()
	keyPEM, certPEM, err := token.Generate("ES256", "registry-pass", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return keyPEM, certPEM
}

func freeAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func writeJSONL(t *testing.T, path string, events []*nip01.Event) {
	var b strings.Builder
	for _, ev := range events {
		data, _ := json.Marshal(ev)
		b.Write(data)
		b.WriteByte('\n')
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func startPass(t *testing.T, o passOpts) *pass {
	t.Helper()
	dir := t.TempDir()
	p := &pass{t: t, dir: dir, addr: freeAddr(t),
		certPEM: filepath.Join(dir, "pass.crt"), keyPEM: filepath.Join(dir, "pass.key"),
		members: filepath.Join(dir, "members.jsonl"), grants: filepath.Join(dir, "grants.yaml")}
	// A hostname, not an IP literal: go-containerregistry refuses token
	// realms on private IP addresses.
	_, port, _ := net.SplitHostPort(p.addr)
	p.realm = "http://localhost:" + port + "/token"
	if o.realmHost != "" {
		p.realm = "http://" + net.JoinHostPort(o.realmHost, port) + "/token"
		p.addr = "0.0.0.0:" + port
	}

	keyPEM, certPEM := generate(t)
	os.WriteFile(p.keyPEM, keyPEM, 0o600)
	os.WriteFile(p.certPEM, certPEM, 0o644)
	os.Chmod(dir, 0o755)

	g := o.grants
	if g == "" {
		g = fmt.Sprintf(defaultGrants, builder.Npub, staticHash, mallory.Npub)
	}
	os.WriteFile(p.grants, []byte(g), 0o600)
	if o.members == nil {
		o.members = []*nip01.Event{authority.Member(30078, "member:", "alice", alice.Pub, "alive", time.Now().Add(-time.Minute))}
	}
	writeJSONL(t, p.members, o.members)

	source := fmt.Sprintf("{file: {path: %s, pollInterval: 1s}}", p.members)
	if o.relayURL != "" {
		source = fmt.Sprintf("{relay: {urls: [%s], reader: {keyFile: %s}, resync: 1m}}", o.relayURL, p.readerKey())
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	os.WriteFile(cfgPath, []byte(fmt.Sprintf(`
realm: %s
services: [%s]
server: {listen: %q, requireTLS: false}
token: {signingKeyFile: %s, certificateFile: %s}
membership:
  authorities: [%s]
  sources: [%s]
grants: {file: %s, reload: none}
logging: {level: warn}
%s`, p.realm, service, p.addr, p.keyPEM, p.certPEM, authority.Npub, source, p.grants, o.extra)), 0o600)

	cfg, _, err := config.Load(cfgPath, o.env)
	if err != nil {
		t.Fatal(err)
	}
	a, err := app.Build(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	l, err := a.Server.Listen()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx, l) }()
	t.Cleanup(func() { cancel(); <-done })
	p.app = a
	waitFor(t, 10*time.Second, func() bool { return a.Store.Fresh() })
	return p
}

func (p *pass) readerKey() string {
	path := filepath.Join(p.dir, "reader.nsec")
	os.WriteFile(path, []byte(testkit.NewKey("reader").Nsec), 0o600)
	return path
}

// setMembers replaces the membership file (as a ConfigMap update would).
func (p *pass) setMembers(events ...*nip01.Event) { writeJSONL(p.t, p.members, events) }

// creds returns Basic credentials for k: npub and a fresh login event.
func (p *pass) creds(k testkit.Key) *authn.Basic {
	ev := k.LoginEvent(p.realm, time.Now(), 30*time.Minute)
	return &authn.Basic{Username: k.Npub, Password: testkit.Password(ev)}
}

// tokenFor asks registry-pass for a token directly.
func (p *pass) tokenFor(t *testing.T, auth *authn.Basic, scopes ...string) string {
	t.Helper()
	q := url.Values{"service": {service}}
	for _, s := range scopes {
		q.Add("scope", s)
	}
	req, _ := http.NewRequest("GET", p.realm+"?"+q.Encode(), nil)
	if auth != nil {
		req.SetBasicAuth(auth.Username, auth.Password)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("token request: %d %s", resp.StatusCode, body)
	}
	var b struct{ Token string }
	json.NewDecoder(resp.Body).Decode(&b)
	return b.Token
}

// startRegistryV3 runs Distribution v3 in-process in token mode, trusting
// only registry-pass's certificate.
func startRegistryV3(t *testing.T, p *pass) string {
	t.Helper()
	cfg := &configuration.Configuration{
		Storage: configuration.Storage{
			"inmemory":    configuration.Parameters{},
			"delete":      configuration.Parameters{"enabled": true},
			"maintenance": configuration.Parameters{"uploadpurging": map[any]any{"enabled": false}},
		},
		Auth: configuration.Auth{"token": configuration.Parameters{
			"realm": p.realm, "service": service, "issuer": "registry-pass", "rootcertbundle": p.certPEM,
		}},
		Catalog: configuration.Catalog{MaxEntries: 100},
	}
	cfg.Log.Level = "error"
	cfg.Log.AccessLog.Disabled = true
	reg := httptest.NewServer(handlers.NewApp(context.Background(), cfg))
	t.Cleanup(reg.Close)
	return strings.TrimPrefix(reg.URL, "http://")
}

func ref(t *testing.T, host, repo string) name.Reference {
	r, err := name.ParseReference(host+"/"+repo, name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func randomImage(t *testing.T, layers int) v1.Image {
	img, err := random.Image(512*1024, int64(layers))
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func push(t *testing.T, host, repo string, img v1.Image, auth authn.Authenticator) error {
	return remote.Write(ref(t, host, repo), img, remote.WithAuth(auth))
}

func pull(t *testing.T, host, repo string, auth authn.Authenticator) (v1.Image, error) {
	img, err := remote.Image(ref(t, host, repo), remote.WithAuth(auth))
	if err != nil {
		return nil, err
	}
	// Fetch every layer so blob access is exercised too.
	layers, err := img.Layers()
	if err != nil {
		return nil, err
	}
	for _, l := range layers {
		rc, err := l.Compressed()
		if err != nil {
			return nil, err
		}
		_, err = io.Copy(io.Discard, rc)
		rc.Close()
		if err != nil {
			return nil, err
		}
	}
	return img, nil
}

func mustDenied(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: succeeded, want denied", what)
	}
	msg := err.Error()
	if !strings.Contains(msg, "UNAUTHORIZED") && !strings.Contains(msg, "DENIED") && !strings.Contains(msg, "401") && !strings.Contains(msg, "403") {
		t.Fatalf("%s: unexpected error %v", what, err)
	}
}

func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}
