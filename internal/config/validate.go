package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/ohstr/nmilat/nip19"
)

// ValidationError lists every problem found, one per line.
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string {
	return "invalid configuration:\n  - " + strings.Join(e.Problems, "\n  - ")
}

type checker struct{ problems []string }

func (c *checker) addf(format string, args ...any) {
	c.problems = append(c.problems, fmt.Sprintf(format, args...))
}

func (c *checker) oneOf(path, v string, allowed ...string) {
	if !slices.Contains(allowed, v) {
		c.addf("%s: %q is not one of %s", path, v, strings.Join(allowed, " | "))
	}
}

func (c *checker) path(name, v string) {
	if !strings.HasPrefix(v, "/") || strings.ContainsAny(v, "?# ") {
		c.addf("%s: %q must be an absolute URL path", name, v)
	}
}

// Validate checks every setting and the cross-checks of PLAN.md §8, and
// normalizes public keys to lowercase hex. It returns a *ValidationError.
func (cfg *Config) Validate() error {
	c := &checker{}

	cfg.validateTop(c)
	cfg.validateServer(c)
	cfg.validateLogin(c)
	cfg.validateToken(c)
	cfg.validateMembership(c)
	cfg.validateGrants(c)
	cfg.validateRateLimit(c)
	c.oneOf("logging.level", cfg.Logging.Level, "debug", "info", "warn", "error")
	c.oneOf("logging.format", cfg.Logging.Format, "json", "text")

	if len(c.problems) > 0 {
		return &ValidationError{Problems: c.problems}
	}
	return nil
}

func (cfg *Config) validateTop(c *checker) {
	if cfg.Realm == "" {
		c.addf("realm: required")
	} else if u, err := url.Parse(cfg.Realm); err != nil || !u.IsAbs() || u.Host == "" {
		c.addf("realm: %q is not an absolute URL", cfg.Realm)
	} else {
		if u.Scheme != "https" && u.Scheme != "http" {
			c.addf("realm: scheme must be https or http")
		}
		if u.Scheme == "http" && cfg.Server.RequireTLS {
			c.addf("realm: must be https while server.requireTLS is true")
		}
		if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			c.addf("realm: must not carry a query, fragment or user info")
		}
	}
	if len(cfg.Services) == 0 {
		c.addf("services: at least one service is required")
	}
	seen := map[string]bool{}
	for _, s := range cfg.Services {
		if strings.TrimSpace(s) == "" || strings.ContainsAny(s, " \t\"") {
			c.addf("services: invalid service name %q", s)
		}
		if seen[s] {
			c.addf("services: %q listed twice", s)
		}
		seen[s] = true
	}
	if cfg.Issuer == "" {
		c.addf("issuer: must not be empty")
	}
}

func (cfg *Config) validateServer(c *checker) {
	s := cfg.Server
	if _, _, err := net.SplitHostPort(s.Listen); err != nil {
		c.addf("server.listen: %q is not host:port", s.Listen)
	}
	if (s.TLS.CertFile == "") != (s.TLS.KeyFile == "") {
		c.addf("server.tls: certFile and keyFile must be set together")
	}
	c.oneOf("server.tls.minVersion", s.TLS.MinVersion, "1.2", "1.3")
	for _, p := range s.TrustedProxies {
		if _, err := ParseCIDR(p); err != nil {
			c.addf("server.trustedProxies: %v", err)
		}
	}
	if s.RequireTLS && !s.TLS.Enabled() && len(s.TrustedProxies) == 0 {
		c.addf("server.requireTLS: needs server.tls or server.trustedProxies (a TLS-terminating proxy)")
	}
	c.path("server.tokenPath", s.TokenPath)
	c.oneOf("server.postToken", s.PostToken, "notFound", "methodNotAllowed")
	for name, d := range map[string]Duration{
		"server.readTimeout": s.ReadTimeout, "server.writeTimeout": s.WriteTimeout,
		"server.idleTimeout": s.IdleTimeout,
	} {
		if d <= 0 {
			c.addf("%s: must be positive", name)
		}
	}
	if s.MaxHeaderBytes < 4096 {
		c.addf("server.maxHeaderBytes: %d is too small for a login event (min 4096)", s.MaxHeaderBytes)
	}

	a := cfg.Admin
	if a.Listen != "" {
		if _, _, err := net.SplitHostPort(a.Listen); err != nil {
			c.addf("admin.listen: %q is not host:port", a.Listen)
		}
		if a.Listen == s.Listen {
			c.addf("admin.listen: must differ from server.listen (leave empty to share it)")
		}
	}
	c.path("admin.healthPath", a.HealthPath)
	c.path("admin.readyPath", a.ReadyPath)
	c.path("admin.metricsPath", a.MetricsPath)
	if a.Listen == "" {
		for _, p := range []string{a.HealthPath, a.ReadyPath, a.MetricsPath} {
			if p == s.TokenPath {
				c.addf("admin: path %q collides with server.tokenPath", p)
			}
		}
	}
}

func (cfg *Config) validateLogin(c *checker) {
	l := cfg.Login
	if l.Kind <= 0 || l.Kind > 65535 {
		c.addf("login.kind: %d is not a valid event kind", l.Kind)
	}
	if l.MaxLifetime <= 0 {
		c.addf("login.maxLifetime: must be positive")
	}
	if l.MaxLifetime <= l.MinRemaining {
		c.addf("login.maxLifetime (%s) must be greater than login.minRemaining (%s)", l.MaxLifetime, l.MinRemaining)
	}
	if len(l.UsernameFormats) == 0 {
		c.addf("login.usernameFormats: at least one format is required")
	}
	for _, f := range l.UsernameFormats {
		c.oneOf("login.usernameFormats", f, "npub", "nprofile", "hex")
	}
	if l.CacheSize < 0 {
		c.addf("login.cacheSize: must not be negative")
	}
}

func (cfg *Config) validateToken(c *checker) {
	t := cfg.Token
	if t.SigningKeyFile == "" {
		c.addf("token.signingKeyFile: required")
	}
	if t.CertificateFile == "" {
		c.addf("token.certificateFile: required")
	}
	c.oneOf("token.algorithm", t.Algorithm, "ES256", "ES384", "RS256")
	c.oneOf("token.kid", t.KID, "auto", "libtrust", "thumbprint", "none")
	if !t.X5C && t.KID == "none" {
		c.addf("token: with x5c false, kid must not be none (the registry could not find the key)")
	}
	if t.MinLifetime.D() < 60*time.Second {
		c.addf("token.minLifetime: %s is below 60s, which Docker rounds up and would use expired tokens", t.MinLifetime)
	}
	if t.Lifetime < t.MinLifetime {
		c.addf("token.lifetime (%s) must be at least token.minLifetime (%s)", t.Lifetime, t.MinLifetime)
	}
	if t.CapToLoginExpiry && cfg.Login.MinRemaining < t.MinLifetime {
		c.addf("login.minRemaining (%s) must be at least token.minLifetime (%s) while token.capToLoginExpiry is true",
			cfg.Login.MinRemaining, t.MinLifetime)
	}
}

func (cfg *Config) validateMembership(c *checker) {
	m := &cfg.Membership
	c.oneOf("membership.nameMismatch", m.NameMismatch, "reject", "useD")
	c.oneOf("membership.resolve", m.Resolve, "latest", "deadWins")
	c.oneOf("membership.duplicatePubkey", m.DuplicatePubkey, "denyAll", "newestWins")
	c.oneOf("membership.emptyPubkey", m.EmptyPubkey, "noAccess")
	c.oneOf("membership.onStale", m.OnStale, "denyMembers", "denyAll", "keepLastView")
	if !m.Enabled {
		return
	}
	if len(m.Authorities) == 0 {
		c.addf("membership.authorities: at least one authority is required when membership is enabled")
	}
	seen := map[string]bool{}
	for i, a := range m.Authorities {
		hex, err := nip19.ParsePublicKey(a)
		if err != nil {
			c.addf("membership.authorities[%d]: %v", i, err)
			continue
		}
		if seen[hex] {
			c.addf("membership.authorities[%d]: duplicate authority", i)
		}
		seen[hex] = true
		m.Authorities[i] = hex
	}
	if m.Kind <= 0 || m.Kind > 65535 {
		c.addf("membership.kind: %d is not a valid event kind", m.Kind)
	} else if m.Kind < 30000 || m.Kind >= 40000 {
		c.addf("membership.kind: %d is not an addressable kind (30000-39999)", m.Kind)
	}
	if m.DPrefix == "" {
		c.addf("membership.dPrefix: must not be empty")
	}
	if m.StaleAfter <= 0 {
		c.addf("membership.staleAfter: must be positive")
	}
	if m.Heartbeat.Enabled {
		if m.Heartbeat.D == "" {
			c.addf("membership.heartbeat.d: required when the heartbeat is enabled")
		} else if strings.HasPrefix(m.Heartbeat.D, m.DPrefix) {
			c.addf("membership.heartbeat.d: %q must not start with membership.dPrefix %q", m.Heartbeat.D, m.DPrefix)
		}
	}
	if len(m.Sources) == 0 {
		c.addf("membership.sources: at least one source is required when membership is enabled")
	}
	for i, s := range m.Sources {
		cfg.validateSource(c, i, s)
	}
}

func (cfg *Config) validateSource(c *checker, i int, s Source) {
	where := fmt.Sprintf("membership.sources[%d]", i)
	set := 0
	for _, ok := range []bool{s.Relay != nil, s.File != nil, s.HTTP != nil} {
		if ok {
			set++
		}
	}
	if set != 1 {
		c.addf("%s: exactly one of relay, file or http is required", where)
		return
	}
	stale := cfg.Membership.StaleAfter
	switch {
	case s.Relay != nil:
		r := s.Relay
		if len(r.URLs) == 0 {
			c.addf("%s.relay.urls: at least one relay URL is required", where)
		}
		for _, raw := range r.URLs {
			u, err := url.Parse(raw)
			if err != nil || (u.Scheme != "ws" && u.Scheme != "wss") || u.Host == "" {
				c.addf("%s.relay.urls: %q is not a ws:// or wss:// URL", where, raw)
			}
		}
		if r.Reader != nil {
			if (r.Reader.KeyFile == "") == (r.Reader.Signer == "") {
				c.addf("%s.relay.reader: exactly one of keyFile or signer is required", where)
			}
			if sg := r.Reader.Signer; sg != "" && !strings.HasPrefix(sg, "bunker://") && !strings.HasPrefix(sg, "bunker+unix://") {
				c.addf("%s.relay.reader.signer: must be a bunker:// or bunker+unix:// URI", where)
			}
		}
		if r.PageSize <= 0 || r.DedupeSize < 0 {
			c.addf("%s.relay: pageSize must be positive and dedupeSize not negative", where)
		}
		if r.Resync >= stale {
			c.addf("%s.relay.resync (%s) must be shorter than membership.staleAfter (%s)", where, r.Resync, stale)
		}
	case s.File != nil:
		if s.File.Path == "" {
			c.addf("%s.file.path: required", where)
		}
		if !s.File.Watching() && s.File.PollInterval >= stale {
			c.addf("%s.file.pollInterval (%s) must be shorter than membership.staleAfter (%s)", where, s.File.PollInterval, stale)
		}
	case s.HTTP != nil:
		u, err := url.Parse(s.HTTP.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			c.addf("%s.http.url: %q is not an http(s) URL", where, s.HTTP.URL)
		}
		if s.HTTP.Interval >= stale {
			c.addf("%s.http.interval (%s) must be shorter than membership.staleAfter (%s)", where, s.HTTP.Interval, stale)
		}
		if s.HTTP.Timeout <= 0 {
			c.addf("%s.http.timeout: must be positive", where)
		}
		for k, v := range s.HTTP.Headers {
			if _, _, err := ResolveFileRef(v, false); err != nil {
				c.addf("%s.http.headers[%s]: %v", where, k, err)
			}
		}
	}
}

func (cfg *Config) validateGrants(c *checker) {
	g := cfg.Grants
	if g.File == "" {
		c.addf("grants.file: required")
	}
	c.oneOf("grants.reload", g.Reload, "none", "sighup", "watch")
	if _, err := regexp.Compile(g.NamePattern); err != nil {
		c.addf("grants.namePattern: %v", err)
	} else if !strings.HasPrefix(g.NamePattern, "^") || !strings.HasSuffix(g.NamePattern, "$") {
		c.addf("grants.namePattern: must be anchored with ^ and $")
	}
}

func (cfg *Config) validateRateLimit(c *checker) {
	r := cfg.RateLimit
	if !r.Enabled {
		return
	}
	if r.Burst < 1 {
		c.addf("rateLimit.burst: must be at least 1")
	}
}

// ParseCIDR parses a CIDR or a single IP address.
func ParseCIDR(s string) (*net.IPNet, error) {
	if !strings.Contains(s, "/") {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("%q is not an IP address or CIDR", s)
		}
		bits := 128
		if ip.To4() != nil {
			ip, bits = ip.To4(), 32
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, nil
	}
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		return nil, fmt.Errorf("%q is not an IP address or CIDR", s)
	}
	return n, nil
}

var fileRef = regexp.MustCompile(`\{file:([^}]+)\}`)

// ErrInlineSecret flags a header value that holds a credential inline.
var ErrInlineSecret = errors.New("credentials must come from a file: use {file:/path}")

// ResolveFileRef replaces every {file:/path} in v with that file's trimmed
// contents when read is true. Without read it only checks the syntax and
// that an Authorization-looking value doesn't carry an inline credential.
func ResolveFileRef(v string, read bool) (string, bool, error) {
	refs := fileRef.FindAllStringSubmatch(v, -1)
	if len(refs) == 0 {
		lower := strings.ToLower(v)
		if strings.HasPrefix(lower, "bearer ") || strings.HasPrefix(lower, "basic ") || strings.HasPrefix(lower, "token ") {
			return "", false, ErrInlineSecret
		}
		return v, false, nil
	}
	if !read {
		return v, true, nil
	}
	var err error
	out := fileRef.ReplaceAllStringFunc(v, func(m string) string {
		path := fileRef.FindStringSubmatch(m)[1]
		data, rerr := readSecret(path)
		if rerr != nil && err == nil {
			err = rerr
		}
		return data
	})
	return out, true, err
}
