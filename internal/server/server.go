// Package server serves the token endpoint and the admin endpoints
// (PLAN.md §4 and §7).
package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ohstr/registry-pass/internal/config"
	"github.com/ohstr/registry-pass/internal/grants"
	"github.com/ohstr/registry-pass/internal/login"
	"github.com/ohstr/registry-pass/internal/membership"
	"github.com/ohstr/registry-pass/internal/token"
)

type relayState = membership.RelayState

// Source is a membership source as the server sees it.
type Source interface {
	Name() string
	LastSync() time.Time
}

// Deps are the parts a Server is built from.
type Deps struct {
	Config   *config.Config
	Verifier *login.Verifier
	Issuer   *token.Issuer
	Policy   *grants.Policy
	Store    *membership.Store // nil when membership is disabled
	Sources  []Source
	Log      *slog.Logger
	Now      func() time.Time
}

// Server handles token requests.
type Server struct {
	cfg      *config.Config
	verifier *login.Verifier
	issuer   *token.Issuer
	policy   atomic.Pointer[grants.Policy]
	static   *grants.StaticAuth
	store    *membership.Store
	sources  []Source
	log      *slog.Logger
	now      func() time.Time
	proxies  proxies
	metrics  *metrics

	perIP, perPubkey, perStatic, failures *limiter
}

// maxScopes bounds the scope parameters of one request.
const maxScopes = 64

// maxRateKeys bounds each rate limiter's memory.
const maxRateKeys = 100000

// New builds a Server.
func New(d Deps) (*Server, error) {
	if d.Config == nil || d.Verifier == nil || d.Issuer == nil || d.Policy == nil {
		return nil, errors.New("server: missing dependency")
	}
	if d.Log == nil {
		d.Log = slog.New(slog.DiscardHandler)
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	s := &Server{
		cfg: d.Config, verifier: d.Verifier, issuer: d.Issuer, store: d.Store, sources: d.Sources,
		log: d.Log, now: d.Now, static: grants.NewStaticAuth(d.Config.Grants.StaticUserCacheTTL.D()),
	}
	s.policy.Store(d.Policy)
	for _, p := range d.Config.Server.TrustedProxies {
		n, err := config.ParseCIDR(p)
		if err != nil {
			return nil, err
		}
		s.proxies = append(s.proxies, n)
	}
	if rl := d.Config.RateLimit; rl.Enabled {
		s.perIP = newLimiter(rl.PerIP.PerSecond(), rl.Burst, maxRateKeys)
		s.perPubkey = newLimiter(rl.PerPubkey.PerSecond(), rl.Burst, maxRateKeys)
		s.perStatic = newLimiter(rl.PerStaticUser.PerSecond(), rl.Burst, maxRateKeys)
		s.failures = newLimiter(rl.FailuresPerIP.PerSecond(), rl.Burst, maxRateKeys)
	}
	s.metrics = newMetrics(s)
	return s, nil
}

// SetPolicy swaps in a reloaded grants policy.
func (s *Server) SetPolicy(p *grants.Policy) { s.policy.Store(p) }

// Reloaded records a grants reload attempt.
func (s *Server) Reloaded(ok bool) {
	if ok {
		s.metrics.reloads.WithLabelValues("ok").Inc()
	} else {
		s.metrics.reloads.WithLabelValues("error").Inc()
	}
}

// Handler serves the token endpoint, plus the admin endpoints when they
// share the listener.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(s.cfg.Server.TokenPath, s.serveToken)
	if s.cfg.Admin.Listen == "" {
		s.mountAdmin(mux)
	}
	return securityHeaders(mux)
}

// AdminHandler serves health, readiness and metrics.
func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	s.mountAdmin(mux)
	return securityHeaders(mux)
}

func (s *Server) mountAdmin(mux *http.ServeMux) {
	a := s.cfg.Admin
	mux.HandleFunc(a.HealthPath, func(w http.ResponseWriter, r *http.Request) {
		writeText(w, http.StatusOK, "ok\n")
	})
	mux.HandleFunc(a.ReadyPath, func(w http.ResponseWriter, r *http.Request) {
		// Readiness is about this process, never membership freshness, so
		// static users keep working when the membership view is stale.
		if time.Until(s.issuer.NotAfter()) <= 0 {
			writeText(w, http.StatusServiceUnavailable, "signing certificate expired\n")
			return
		}
		writeText(w, http.StatusOK, "ready\n")
	})
	if a.Metrics {
		mux.Handle(a.MetricsPath, promHandler(s.metrics.reg))
	}
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		h.ServeHTTP(w, r)
	})
}

func writeText(w http.ResponseWriter, code int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(body))
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="registry-pass"`)
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string][]apiError{"errors": {{Code: code, Message: msg}}})
}

type tokenResponse struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	IssuedAt    string `json:"issued_at"`
}

// decision is what gets logged for one request: never credentials.
type decision struct {
	ip, subject, kind, service, result, reason string
	requested                                  []grants.Scope
	granted                                    []grants.Access
}

func (s *Server) record(d decision) {
	s.metrics.logins.WithLabelValues(d.result, d.reason).Inc()
	if d.result == "granted" && !s.cfg.Logging.LogGranted {
		return
	}
	attrs := []any{"ip", d.ip, "subject", d.subject, "kind", d.kind, "service", d.service,
		"result", d.result, "reason", d.reason, "requested", scopeStrings(d.requested), "granted", accessStrings(d.granted)}
	if d.result == "granted" {
		s.log.Info("token", attrs...)
	} else {
		s.log.Warn("token", attrs...)
	}
}

func scopeStrings(sc []grants.Scope) []string {
	out := make([]string, 0, len(sc))
	for _, x := range sc {
		out = append(out, x.Type+":"+x.Name+":"+strings.Join(x.Actions, ","))
	}
	return out
}

func accessStrings(ac []grants.Access) []string {
	out := make([]string, 0, len(ac))
	for _, x := range ac {
		out = append(out, x.Type+":"+x.Name+":"+strings.Join(x.Actions, ","))
	}
	return out
}

func (s *Server) serveToken(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
	case http.MethodPost:
		// The OAuth2 flow isn't supported; clients fall back to GET.
		if s.cfg.Server.PostToken == "methodNotAllowed" {
			w.Header().Set("Allow", "GET")
			writeError(w, http.StatusMethodNotAllowed, "UNSUPPORTED", "use GET")
		} else {
			http.NotFound(w, r)
		}
		return
	default:
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, "UNSUPPORTED", "use GET")
		return
	}

	d := decision{ip: s.proxies.clientIP(r), result: "denied"}
	defer func() { s.record(d) }()

	if s.cfg.Server.RequireTLS && !s.proxies.secure(r) {
		d.reason = "tls_required"
		writeError(w, http.StatusForbidden, "DENIED", "TLS is required")
		return
	}
	if !s.perIP.allow(d.ip) {
		d.reason = "rate_limited_ip"
		s.rateLimited(w, "ip")
		return
	}
	if !s.failures.peek(d.ip) {
		d.reason = "rate_limited_failures"
		s.rateLimited(w, "failures")
		return
	}

	q := r.URL.Query()
	d.service = q.Get("service")
	if len(q["service"]) != 1 || !slices.Contains(s.cfg.Services, d.service) {
		d.reason = "unknown_service"
		writeError(w, http.StatusBadRequest, "UNSUPPORTED", "unknown service")
		return
	}
	if len(q["scope"]) > maxScopes {
		d.reason = "too_many_scopes"
		writeError(w, http.StatusBadRequest, "UNSUPPORTED", "too many scopes")
		return
	}
	d.requested = grants.ParseScopes(q["scope"])

	subject, expires, ok := s.authenticate(w, r, &d)
	if !ok {
		return
	}
	policy := s.policy.Load()
	d.granted = policy.Authorize(subject, d.requested)

	now := s.now()
	exp := now.Add(s.cfg.Token.Lifetime.D())
	if !expires.IsZero() && s.cfg.Token.CapToLoginExpiry && expires.Before(exp) {
		exp = expires
	}
	if exp.Sub(now) < s.cfg.Token.MinLifetime.D() {
		d.reason = "login_expiring"
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "login event expires too soon")
		return
	}
	tok, err := s.issuer.IssueAt(now, d.subject, d.service, d.granted, exp)
	if err != nil {
		d.reason = "issue_failed"
		s.log.Error("issue token", "err", err)
		writeError(w, http.StatusInternalServerError, "UNKNOWN", "could not issue a token")
		return
	}
	d.result, d.reason = "granted", "ok"
	s.metrics.tokens.WithLabelValues(d.kind).Inc()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(tokenResponse{
		Token: tok.Raw, AccessToken: tok.Raw,
		ExpiresIn: int64(tok.ExpiresAt.Sub(tok.IssuedAt).Seconds()),
		IssuedAt:  tok.IssuedAt.UTC().Format(time.RFC3339),
	})
}

func (s *Server) rateLimited(w http.ResponseWriter, which string) {
	s.metrics.rateLimited.WithLabelValues(which).Inc()
	w.Header().Set("Retry-After", "60")
	writeError(w, http.StatusTooManyRequests, "TOOMANYREQUESTS", "too many requests")
}

// authFailed counts a failed login against the client's IP.
func (s *Server) authFailed(w http.ResponseWriter, d *decision, reason string) {
	d.reason = reason
	s.failures.allow(d.ip)
	writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
}

// authenticate resolves the request's subject. expires is the login
// event's expiration for Nostr logins, zero otherwise.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request, d *decision) (grants.Subject, time.Time, bool) {
	policy := s.policy.Load()
	if r.Header.Get("Authorization") == "" {
		d.kind, d.subject = "anonymous", ""
		if !policy.HasAnonymous() {
			d.reason = "no_credentials"
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
			return grants.Subject{}, time.Time{}, false
		}
		return grants.Subject{Anonymous: true}, time.Time{}, true
	}
	user, pass, ok := r.BasicAuth()
	if !ok || user == "" {
		s.authFailed(w, d, "bad_authorization_header")
		return grants.Subject{}, time.Time{}, false
	}
	if acct := r.URL.Query().Get("account"); acct != "" && acct != user {
		s.authFailed(w, d, "account_mismatch")
		return grants.Subject{}, time.Time{}, false
	}

	if policy.IsStaticUser(user) {
		d.kind, d.subject = "static", user
		if !s.static.Check(policy, user, pass) {
			s.authFailed(w, d, "bad_password")
			return grants.Subject{}, time.Time{}, false
		}
		if !s.perStatic.allow(user) {
			d.reason = "rate_limited_static_user"
			s.rateLimited(w, "static_user")
			return grants.Subject{}, time.Time{}, false
		}
		return grants.Subject{StaticUser: user}, time.Time{}, true
	}

	d.kind = "nostr"
	id, err := s.verifier.Verify(user, pass, d.service)
	if err != nil {
		s.authFailed(w, d, string(login.ReasonOf(err)))
		return grants.Subject{}, time.Time{}, false
	}
	d.subject = id.Pubkey
	// Only a verified signature spends the pubkey's quota, so nobody can
	// exhaust someone else's limit with forged requests.
	if !s.perPubkey.allow(id.Pubkey) {
		d.reason = "rate_limited_pubkey"
		s.rateLimited(w, "pubkey")
		return grants.Subject{}, time.Time{}, false
	}
	if policy.Denied(id.Pubkey) {
		d.reason = "denied"
		writeError(w, http.StatusForbidden, "DENIED", "access denied")
		return grants.Subject{}, time.Time{}, false
	}
	subject := grants.Subject{Pubkey: id.Pubkey}
	if s.store != nil {
		l := s.store.Lookup(id.Pubkey)
		if l.DenyAll {
			d.reason = "membership_stale"
			writeError(w, http.StatusServiceUnavailable, "UNAVAILABLE", "membership is unavailable")
			return grants.Subject{}, time.Time{}, false
		}
		subject.MemberName = l.Name
	}
	return subject, id.Expires, true
}
