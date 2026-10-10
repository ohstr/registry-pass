// Package helper is the Docker credential helper: it answers
// `get` with the client's npub and a freshly signed login event.
package helper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip19"
	"github.com/ohstr/nmilat/nip46"
	"github.com/ohstr/nmilat/nip46/bunker"
	"github.com/ohstr/nmilat/nipLS"
	"gopkg.in/yaml.v3"
)

// ErrNotFound is the message Docker expects when a helper has no
// credentials for a registry; Docker then proceeds without them.
var ErrNotFound = errors.New("credentials not found in native keychain")

// EnvConfig names the helper's config file.
const EnvConfig = "DOCKER_CREDENTIAL_REGISTRY_PASS_CONFIG"

// Registry is one registry's helper settings.
type Registry struct {
	Realm         string        `yaml:"realm"`
	Service       string        `yaml:"service"`
	Signer        string        `yaml:"signer"`
	Lifetime      time.Duration `yaml:"lifetime"`
	RefreshAt     float64       `yaml:"refreshAt"`
	SignerTimeout time.Duration `yaml:"signerTimeout"`
}

// Config is the helper's config file.
type Config struct {
	CacheDir   string              `yaml:"cacheDir"`
	Registries map[string]Registry `yaml:"registries"`
}

// LoadConfig reads the helper config at path.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	norm := map[string]Registry{}
	for host, r := range c.Registries {
		if r.Lifetime == 0 {
			r.Lifetime = time.Hour
		}
		if r.RefreshAt == 0 {
			r.RefreshAt = 0.5
		}
		if r.SignerTimeout == 0 {
			r.SignerTimeout = 60 * time.Second
		}
		if r.Realm == "" || r.Signer == "" {
			return nil, fmt.Errorf("registries[%s]: realm and signer are required", host)
		}
		if r.RefreshAt <= 0 || r.RefreshAt >= 1 {
			return nil, fmt.Errorf("registries[%s]: refreshAt must be between 0 and 1", host)
		}
		if r.Lifetime < 5*time.Minute {
			return nil, fmt.Errorf("registries[%s]: lifetime must be at least 5m", host)
		}
		norm[NormalizeHost(host)] = r
	}
	c.Registries = norm
	return &c, nil
}

// DefaultConfigPath is $XDG_CONFIG_HOME/registry-pass/helper.yaml.
func DefaultConfigPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "helper.yaml"
	}
	return filepath.Join(dir, "registry-pass", "helper.yaml")
}

// NormalizeHost reduces a server URL Docker passes ("https://r.example/v2/",
// "r.example:443") to a lowercase host[:port] without default ports.
func NormalizeHost(server string) string {
	s := strings.TrimSpace(server)
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return strings.ToLower(strings.TrimSpace(server))
	}
	host, port := strings.ToLower(u.Hostname()), u.Port()
	if port == "443" || (port == "80" && u.Scheme == "http") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		return host + ":" + port
	}
	return host
}

// Credentials is the `get` answer.
type Credentials struct {
	ServerURL string `json:"ServerURL,omitempty"`
	Username  string `json:"Username"`
	Secret    string `json:"Secret"`
}

// Signer signs login events.
type Signer interface {
	PubKey() string
	Sign(ctx context.Context, ev *nip01.Event) error
}

// Helper answers credential requests.
type Helper struct {
	Config *Config
	Now    func() time.Time
	// OpenSigner opens a signer URI; tests replace it.
	OpenSigner func(ctx context.Context, uri, sessionPath string, timeout time.Duration) (Signer, func(), error)
}

func (h *Helper) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *Helper) cacheDir() (string, error) {
	if h.Config.CacheDir != "" {
		return h.Config.CacheDir, nil
	}
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "registry-pass"), nil
}

type cached struct {
	Username string    `json:"username"`
	Secret   string    `json:"secret"`
	Expires  time.Time `json:"expires"`
	Lifetime string    `json:"lifetime"`
	Realm    string    `json:"realm"`
}

// Get returns credentials for serverURL.
func (h *Helper) Get(ctx context.Context, serverURL string) (Credentials, error) {
	host := NormalizeHost(serverURL)
	reg, ok := h.Config.Registries[host]
	if !ok {
		return Credentials{}, ErrNotFound
	}
	dir, err := h.cacheDir()
	if err != nil {
		return Credentials{}, err
	}
	key := sha256.Sum256([]byte(host + "\x00" + reg.Realm + "\x00" + reg.Signer))
	name := hex.EncodeToString(key[:8])
	cachePath := filepath.Join(dir, name+".json")

	if c, ok := readCache(cachePath); ok && c.Realm == reg.Realm {
		left := c.Expires.Sub(h.now())
		if left > time.Duration(float64(reg.Lifetime)*reg.RefreshAt) {
			return Credentials{ServerURL: serverURL, Username: c.Username, Secret: c.Secret}, nil
		}
	}

	open := h.OpenSigner
	if open == nil {
		open = OpenSigner
	}
	signer, closeFn, err := open(ctx, reg.Signer, filepath.Join(dir, name+".session"), reg.SignerTimeout)
	if err != nil {
		return Credentials{}, err
	}
	defer closeFn()

	now := h.now()
	exp := now.Add(reg.Lifetime)
	tags := [][]string{{"u", reg.Realm}, {"method", "GET"}, {"expiration", strconv.FormatInt(exp.Unix(), 10)}}
	if reg.Service != "" {
		tags = append(tags, []string{"service", reg.Service})
	}
	ev := nip01.NewEvent(27235, "", tags...)
	ev.CreatedAt = uint64(now.Unix())
	ev.PubKey = signer.PubKey()
	sctx, cancel := context.WithTimeout(ctx, reg.SignerTimeout)
	defer cancel()
	if err := signer.Sign(sctx, ev); err != nil {
		return Credentials{}, fmt.Errorf("sign login event: %w", err)
	}
	if err := ev.Verify(); err != nil || ev.Kind != 27235 {
		return Credentials{}, fmt.Errorf("the signer returned an invalid event")
	}
	npub, err := nip19.EncodePublicKey(ev.PubKey)
	if err != nil {
		return Credentials{}, err
	}
	data, _ := json.Marshal(ev)
	secret := encodePassword(data)
	_ = writeCache(dir, cachePath, cached{Username: npub, Secret: secret, Expires: exp, Lifetime: reg.Lifetime.String(), Realm: reg.Realm})
	return Credentials{ServerURL: serverURL, Username: npub, Secret: secret}, nil
}

func readCache(path string) (cached, bool) {
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0o077 != 0 {
		return cached{}, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cached{}, false
	}
	var c cached
	if json.Unmarshal(data, &c) != nil || c.Secret == "" {
		return cached{}, false
	}
	return c, true
}

func writeCache(dir, path string, c cached) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".cache-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// OpenSigner opens file://, env:, bunker:// or bunker+unix:// signers.
func OpenSigner(ctx context.Context, uri, sessionPath string, timeout time.Duration) (Signer, func(), error) {
	noop := func() {}
	switch {
	case strings.HasPrefix(uri, "file://"):
		path := strings.TrimPrefix(uri, "file://")
		st, err := os.Stat(path)
		if err != nil {
			return nil, nil, err
		}
		if st.Mode().Perm()&0o077 != 0 {
			return nil, nil, fmt.Errorf("%s is readable by others; chmod 600 it", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, err
		}
		k, err := nip46.NewLocalKey(strings.TrimSpace(string(data)))
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", path, err)
		}
		return k, noop, nil
	case strings.HasPrefix(uri, "env:"):
		name := strings.TrimPrefix(uri, "env:")
		v := os.Getenv(name)
		if v == "" {
			return nil, nil, fmt.Errorf("environment variable %s is empty", name)
		}
		k, err := nip46.NewLocalKey(strings.TrimSpace(v))
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", name, err)
		}
		return k, noop, nil
	case strings.HasPrefix(uri, "bunker+unix://"):
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		c, err := nipLS.Dial(ctx, uri)
		if err != nil {
			return nil, nil, err
		}
		return c, func() { c.Close() }, nil
	case strings.HasPrefix(uri, "bunker://"):
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		opts := bunker.ClientOptions{Perms: "sign_event:27235"}
		if s, ok := readSession(sessionPath); ok {
			if c, err := bunker.Resume(ctx, s, opts); err == nil {
				return c, func() { c.Close() }, nil
			}
		}
		c, err := bunker.Dial(ctx, uri, opts)
		if err != nil {
			return nil, nil, err
		}
		_ = writeSession(sessionPath, c.Session())
		return c, func() { c.Close() }, nil
	}
	return nil, nil, fmt.Errorf("unsupported signer %q (want file://, env:, bunker:// or bunker+unix://)", redactURI(uri))
}

func redactURI(uri string) string {
	if i := strings.Index(uri, "?"); i >= 0 {
		return uri[:i] + "?…"
	}
	return uri
}

func readSession(path string) (bunker.Session, bool) {
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0o077 != 0 {
		return bunker.Session{}, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return bunker.Session{}, false
	}
	var s bunker.Session
	return s, json.Unmarshal(data, &s) == nil && s.ClientKey != ""
}

func writeSession(path string, s bunker.Session) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func encodePassword(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
