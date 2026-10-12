package server

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/ohstr/registry-pass/internal/grants"
	"github.com/ohstr/registry-pass/internal/login"
	"github.com/ohstr/registry-pass/internal/quota"
	"github.com/prometheus/client_golang/prometheus"
)

// Quota endpoints, served on the main listener when the module is on.
const (
	EventsPath  = "/events"
	UsagePath   = "/usage/"
	RebuildPath = "/quota/rebuild"
)

func (s *Server) mountQuota(mux *http.ServeMux) {
	mux.HandleFunc(EventsPath, s.serveEvents)
	mux.HandleFunc(UsagePath, s.serveUsage)
	mux.HandleFunc(RebuildPath, s.serveRebuild)
}

// limitQuota drops push on namespaces at or over their quota, logging and
// returning why.
func (s *Server) limitQuota(d *decision, pubkey string) []string {
	if s.quota == nil {
		return nil
	}
	var refused []quota.Verdict
	d.granted, refused = s.quota.Filter(d.granted, pubkey)
	var out []string
	for _, v := range refused {
		s.metrics.quotaRefused.Inc()
		s.log.Warn(v.Reason(), "subject", d.subject, "namespace", v.Namespace, "used", v.Used, "quota", v.Quota)
		out = append(out, v.Reason())
	}
	return out
}

// bearer checks the events token on a POST.
func (s *Server) bearer(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, "UNSUPPORTED", "use POST")
		return false
	}
	// The registry sends many notifications: only failed tokens are
	// limited, so they don't spend the per-IP budget its clients share.
	ip := s.proxies.clientIP(r)
	if !s.failures.peek(ip) {
		s.rateLimited(w, "failures")
		return false
	}
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || !s.quota.CheckToken(tok) {
		s.failures.allow(ip)
		w.Header().Set("WWW-Authenticate", `Bearer realm="registry-pass"`)
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "a valid bearer token is required")
		return false
	}
	return true
}

// serveEvents takes the registry's notifications and queues recounts.
func (s *Server) serveEvents(w http.ResponseWriter, r *http.Request) {
	if !s.bearer(w, r) {
		return
	}
	n, err := s.quota.Events(r.Body)
	if err != nil {
		s.log.Warn("quota: unreadable notification", "err", err)
		writeError(w, http.StatusBadRequest, "UNSUPPORTED", "not a notification envelope")
		return
	}
	s.metrics.quotaEvents.Add(float64(n))
	w.WriteHeader(http.StatusOK)
}

// serveRebuild recounts everything; `registry-pass quota rebuild` calls it
// when this process holds the store.
func (s *Server) serveRebuild(w http.ResponseWriter, r *http.Request) {
	if !s.bearer(w, r) {
		return
	}
	// A rebuild can outlast the write timeout.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
	sum, err := s.quota.Rebuild(r.Context())
	if err != nil {
		s.log.Error("quota: rebuild failed", "err", err)
		writeError(w, http.StatusBadGateway, "UNAVAILABLE", "rebuild failed: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(sum)
}

// serveUsage reports one namespace's usage to its owner or a read-all
// (catalog) key, who log in as for /token.
func (s *Server) serveUsage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, "UNSUPPORTED", "use GET")
		return
	}
	d := decision{ip: s.proxies.clientIP(r), kind: "usage", result: "denied"}
	if s.cfg.Server.RequireTLS && !s.proxies.secure(r) {
		writeError(w, http.StatusForbidden, "DENIED", "TLS is required")
		return
	}
	if !s.perIP.allow(d.ip) || !s.failures.peek(d.ip) {
		s.rateLimited(w, "ip")
		return
	}
	name := strings.TrimPrefix(r.URL.Path, UsagePath)
	policy := s.policy.Load()
	if strings.Contains(name, "/") || !grants.ValidRepoName(name) {
		writeError(w, http.StatusNotFound, "NAME_UNKNOWN", "not a namespace")
		return
	}
	service := r.URL.Query().Get("service")
	if service == "" {
		service = s.cfg.Services[0]
	}
	if !slices.Contains(s.cfg.Services, service) {
		writeError(w, http.StatusBadRequest, "UNSUPPORTED", "unknown service")
		return
	}
	user, pass, ok := r.BasicAuth()
	if !ok || user == "" {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
		return
	}
	id, err := s.verifier.Verify(user, pass, service)
	if err != nil {
		s.authFailed(w, &d, string(login.ReasonOf(err)))
		return
	}
	if !s.perPubkey.allow(id.Pubkey) {
		s.rateLimited(w, "pubkey")
		return
	}
	owner := false
	if s.store != nil {
		l := s.store.Lookup(id.Pubkey)
		owner = l.Name == name && policy.ValidMemberName(l.Name)
	}
	if policy.Denied(id.Pubkey) || !(owner || policy.ReadAll(id.Pubkey)) {
		writeError(w, http.StatusForbidden, "DENIED", "only the namespace's owner or a read-all key may see its usage")
		return
	}
	if !s.quota.Ready() {
		w.Header().Set("Retry-After", "30")
		writeError(w, http.StatusServiceUnavailable, "UNAVAILABLE", quota.ErrNotReady.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.quota.Usage(name))
}

// quotaCollector exports each namespace's usage and quota.
type quotaCollector struct{ q *quota.Module }

var (
	quotaUsedDesc = prometheus.NewDesc("registry_pass_quota_used_bytes",
		"Bytes of distinct blobs the namespace's tags reach.", []string{"name"}, nil)
	quotaBytesDesc = prometheus.NewDesc("registry_pass_quota_bytes",
		"The namespace's quota (absent when exempt).", []string{"name"}, nil)
	quotaReadyDesc = prometheus.NewDesc("registry_pass_quota_ready",
		"1 once a full recount has completed and usage is known.", nil, nil)
)

func (c *quotaCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- quotaUsedDesc
	ch <- quotaBytesDesc
	ch <- quotaReadyDesc
}

func (c *quotaCollector) Collect(ch chan<- prometheus.Metric) {
	ready := 0.0
	if c.q.Ready() {
		ready = 1
	}
	ch <- prometheus.MustNewConstMetric(quotaReadyDesc, prometheus.GaugeValue, ready)
	for _, ns := range c.q.Names() {
		u := c.q.Usage(ns)
		ch <- prometheus.MustNewConstMetric(quotaUsedDesc, prometheus.GaugeValue, float64(u.Used), ns)
		if !u.Exempt {
			ch <- prometheus.MustNewConstMetric(quotaBytesDesc, prometheus.GaugeValue, float64(u.Quota), ns)
		}
	}
}
