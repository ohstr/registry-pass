package server

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

type metrics struct {
	reg         *prometheus.Registry
	logins      *prometheus.CounterVec
	tokens      *prometheus.CounterVec
	rateLimited *prometheus.CounterVec
	reloads     *prometheus.CounterVec

	quotaRefused prometheus.Counter
	quotaEvents  prometheus.Counter
}

func newMetrics(s *Server) *metrics {
	reg := prometheus.NewRegistry()
	m := &metrics{
		reg: reg,
		logins: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "registry_pass_logins_total", Help: "Token requests by outcome and reason.",
		}, []string{"result", "reason"}),
		tokens: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "registry_pass_tokens_issued_total", Help: "Tokens issued, by subject kind.",
		}, []string{"subject"}),
		rateLimited: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "registry_pass_rate_limited_total", Help: "Requests refused by a rate limit.",
		}, []string{"limit"}),
		reloads: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "registry_pass_grants_reloads_total", Help: "Grants file reloads by result.",
		}, []string{"result"}),
	}
	reg.MustRegister(m.logins, m.tokens, m.rateLimited, m.reloads,
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "registry_pass_certificate_expiry_seconds", Help: "Seconds until the signing certificate expires.",
	}, func() float64 { return time.Until(s.issuer.NotAfter()).Seconds() }))

	// Unregistered when the module is off, so they never show.
	m.quotaRefused = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "registry_pass_quota_push_refused_total", Help: "Pushes left out of a token because the namespace is full.",
	})
	m.quotaEvents = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "registry_pass_quota_recounts_queued_total", Help: "Repository recounts queued from registry notifications.",
	})
	if s.quota != nil {
		reg.MustRegister(m.quotaRefused, m.quotaEvents, &quotaCollector{q: s.quota},
			prometheus.NewCounterFunc(prometheus.CounterOpts{
				Name: "registry_pass_quota_recount_errors_total", Help: "Repository recounts that failed and were retried.",
			}, func() float64 { return float64(s.quota.ScanErrors()) }))
	}

	if s.store != nil {
		reg.MustRegister(
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Name: "registry_pass_membership_members", Help: "Alive members in the view.",
			}, func() float64 { return float64(s.store.Snapshot().Size) }),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Name: "registry_pass_membership_conflicts", Help: "Pubkeys claimed by more than one alive record.",
			}, func() float64 { return float64(s.store.Snapshot().Conflicts) }),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Name: "registry_pass_membership_fresh", Help: "1 when the membership view is fresh.",
			}, func() float64 {
				if s.store.Fresh() {
					return 1
				}
				return 0
			}),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Name: "registry_pass_membership_heartbeat_age_seconds", Help: "Age of the newest authority heartbeat (-1: none).",
			}, func() float64 {
				if age := s.store.HeartbeatAge(); age >= 0 {
					return age.Seconds()
				}
				return -1
			}),
			&storeCollector{s: s},
		)
	}
	return m
}

// storeCollector exports per-source and rejection metrics.
type storeCollector struct{ s *Server }

var (
	sourceAgeDesc = prometheus.NewDesc("registry_pass_membership_source_sync_age_seconds",
		"Seconds since the source last completed a sync (-1: never).", []string{"source"}, nil)
	relayAuthDesc = prometheus.NewDesc("registry_pass_membership_relay_auth_ok",
		"1 when the relay connection authenticated.", []string{"relay"}, nil)
	rejectedDesc = prometheus.NewDesc("registry_pass_membership_events_rejected_total",
		"Membership events refused, by reason.", []string{"reason"}, nil)
)

func (c *storeCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- sourceAgeDesc
	ch <- relayAuthDesc
	ch <- rejectedDesc
}

func (c *storeCollector) Collect(ch chan<- prometheus.Metric) {
	for _, src := range c.s.sources {
		age := -1.0
		if last := src.LastSync(); !last.IsZero() {
			age = time.Since(last).Seconds()
		}
		ch <- prometheus.MustNewConstMetric(sourceAgeDesc, prometheus.GaugeValue, age, src.Name())
		if rs, ok := src.(interface{ States() []relayState }); ok {
			for _, st := range rs.States() {
				v := 0.0
				if st.AuthOK {
					v = 1
				}
				ch <- prometheus.MustNewConstMetric(relayAuthDesc, prometheus.GaugeValue, v, st.URL)
			}
		}
	}
	for reason, n := range c.s.store.Rejections() {
		ch <- prometheus.MustNewConstMetric(rejectedDesc, prometheus.CounterValue, float64(n), string(reason))
	}
}
