// Package config holds registry-pass's settings: the schema, its defaults,
// loading from YAML with environment overrides, and validation.
package config

import "time"

// Config is the whole server configuration (PLAN.md §8).
type Config struct {
	Realm    string   `yaml:"realm"`
	Services []string `yaml:"services"`
	Issuer   string   `yaml:"issuer"`

	Server     Server     `yaml:"server"`
	Admin      Admin      `yaml:"admin"`
	Login      Login      `yaml:"login"`
	Token      Token      `yaml:"token"`
	Membership Membership `yaml:"membership"`
	Grants     Grants     `yaml:"grants"`
	RateLimit  RateLimit  `yaml:"rateLimit"`
	Logging    Logging    `yaml:"logging"`
}

type Server struct {
	Listen         string   `yaml:"listen"`
	TLS            TLS      `yaml:"tls"`
	RequireTLS     bool     `yaml:"requireTLS"`
	TrustedProxies []string `yaml:"trustedProxies"`
	TokenPath      string   `yaml:"tokenPath"`
	PostToken      string   `yaml:"postToken"`
	ReadTimeout    Duration `yaml:"readTimeout"`
	WriteTimeout   Duration `yaml:"writeTimeout"`
	IdleTimeout    Duration `yaml:"idleTimeout"`
	MaxHeaderBytes int      `yaml:"maxHeaderBytes"`
	ShutdownGrace  Duration `yaml:"shutdownGrace"`
}

type TLS struct {
	CertFile   string `yaml:"certFile"`
	KeyFile    string `yaml:"keyFile"`
	MinVersion string `yaml:"minVersion"`
}

// Enabled reports whether the server terminates TLS itself.
func (t TLS) Enabled() bool { return t.CertFile != "" || t.KeyFile != "" }

type Admin struct {
	Listen      string `yaml:"listen"`
	HealthPath  string `yaml:"healthPath"`
	ReadyPath   string `yaml:"readyPath"`
	MetricsPath string `yaml:"metricsPath"`
	Metrics     bool   `yaml:"metrics"`
}

type Login struct {
	Kind              int      `yaml:"kind"`
	MaxLifetime       Duration `yaml:"maxLifetime"`
	MinRemaining      Duration `yaml:"minRemaining"`
	ClockSkew         Duration `yaml:"clockSkew"`
	RequireServiceTag bool     `yaml:"requireServiceTag"`
	UsernameFormats   []string `yaml:"usernameFormats"`
	CacheSize         int      `yaml:"cacheSize"`
}

type Token struct {
	SigningKeyFile    string   `yaml:"signingKeyFile"`
	CertificateFile   string   `yaml:"certificateFile"`
	ChainFile         string   `yaml:"chainFile"`
	Algorithm         string   `yaml:"algorithm"`
	Lifetime          Duration `yaml:"lifetime"`
	MinLifetime       Duration `yaml:"minLifetime"`
	CapToLoginExpiry  bool     `yaml:"capToLoginExpiry"`
	X5C               bool     `yaml:"x5c"`
	KID               string   `yaml:"kid"`
	CertExpiryWarning Duration `yaml:"certExpiryWarning"`
}

type Membership struct {
	Enabled         bool      `yaml:"enabled"`
	Authorities     []string  `yaml:"authorities"`
	Kind            int       `yaml:"kind"`
	DPrefix         string    `yaml:"dPrefix"`
	NameMismatch    string    `yaml:"nameMismatch"`
	Resolve         string    `yaml:"resolve"`
	FutureSkew      Duration  `yaml:"futureSkew"`
	HonorDeletions  bool      `yaml:"honorDeletions"`
	DuplicatePubkey string    `yaml:"duplicatePubkey"`
	EmptyPubkey     string    `yaml:"emptyPubkey"`
	StaleAfter      Duration  `yaml:"staleAfter"`
	OnStale         string    `yaml:"onStale"`
	Heartbeat       Heartbeat `yaml:"heartbeat"`
	Sources         []Source  `yaml:"sources"`
}

type Heartbeat struct {
	Enabled bool   `yaml:"enabled"`
	D       string `yaml:"d"`
}

// Source is one membership source; exactly one field is set.
type Source struct {
	Relay *RelaySource `yaml:"relay,omitempty"`
	File  *FileSource  `yaml:"file,omitempty"`
	HTTP  *HTTPSource  `yaml:"http,omitempty"`
}

type RelaySource struct {
	URLs        []string `yaml:"urls"`
	Reader      *Reader  `yaml:"reader,omitempty"`
	RequireAuth *bool    `yaml:"requireAuth,omitempty"`
	AuthWait    Duration `yaml:"authWait"`
	Resync      Duration `yaml:"resync"`
	PageSize    int      `yaml:"pageSize"`
	DedupeSize  int      `yaml:"dedupeSize"`
}

// AuthRequired reports whether freshness needs a successful AUTH.
func (r *RelaySource) AuthRequired() bool {
	if r.Reader == nil {
		return false
	}
	return r.RequireAuth == nil || *r.RequireAuth
}

type Reader struct {
	KeyFile       string   `yaml:"keyFile,omitempty"`
	Signer        string   `yaml:"signer,omitempty"`
	SignerTimeout Duration `yaml:"signerTimeout"`
}

type FileSource struct {
	Path         string   `yaml:"path"`
	Watch        *bool    `yaml:"watch,omitempty"`
	PollInterval Duration `yaml:"pollInterval"`
}

// Watching reports whether the file is watched with inotify (default true).
func (f *FileSource) Watching() bool { return f.Watch == nil || *f.Watch }

type HTTPSource struct {
	URL      string            `yaml:"url"`
	Interval Duration          `yaml:"interval"`
	Timeout  Duration          `yaml:"timeout"`
	Headers  map[string]string `yaml:"headers"`
	CAFile   string            `yaml:"caFile"`
}

type Grants struct {
	File               string   `yaml:"file"`
	Reload             string   `yaml:"reload"`
	NamePattern        string   `yaml:"namePattern"`
	AutoReserve        bool     `yaml:"autoReserve"`
	StaticUserCacheTTL Duration `yaml:"staticUserCacheTTL"`
}

type RateLimit struct {
	Enabled       bool `yaml:"enabled"`
	PerIP         Rate `yaml:"perIP"`
	PerPubkey     Rate `yaml:"perPubkey"`
	PerStaticUser Rate `yaml:"perStaticUser"`
	FailuresPerIP Rate `yaml:"failuresPerIP"`
	Burst         int  `yaml:"burst"`
}

type Logging struct {
	Level      string `yaml:"level"`
	Format     string `yaml:"format"`
	LogGranted bool   `yaml:"logGranted"`
}

// Default returns the configuration with every default from PLAN.md §8.
func Default() Config {
	return Config{
		Issuer: "registry-pass",
		Server: Server{
			Listen:         ":5001",
			TLS:            TLS{MinVersion: "1.2"},
			RequireTLS:     true,
			TokenPath:      "/token",
			PostToken:      "notFound",
			ReadTimeout:    Duration(10 * time.Second),
			WriteTimeout:   Duration(10 * time.Second),
			IdleTimeout:    Duration(60 * time.Second),
			MaxHeaderBytes: 16384,
			ShutdownGrace:  Duration(15 * time.Second),
		},
		Admin: Admin{
			HealthPath:  "/healthz",
			ReadyPath:   "/readyz",
			MetricsPath: "/metrics",
			Metrics:     true,
		},
		Login: Login{
			Kind:            27235,
			MaxLifetime:     Duration(time.Hour),
			MinRemaining:    Duration(2 * time.Minute),
			ClockSkew:       Duration(30 * time.Second),
			UsernameFormats: []string{"npub", "nprofile", "hex"},
			CacheSize:       10000,
		},
		Token: Token{
			Algorithm:         "ES256",
			Lifetime:          Duration(5 * time.Minute),
			MinLifetime:       Duration(60 * time.Second),
			CapToLoginExpiry:  true,
			X5C:               true,
			KID:               "auto",
			CertExpiryWarning: Duration(720 * time.Hour),
		},
		Membership: Membership{
			Enabled:         true,
			Kind:            30078,
			DPrefix:         "member:",
			NameMismatch:    "reject",
			Resolve:         "latest",
			FutureSkew:      Duration(30 * time.Second),
			HonorDeletions:  true,
			DuplicatePubkey: "denyAll",
			EmptyPubkey:     "noAccess",
			StaleAfter:      Duration(30 * time.Minute),
			OnStale:         "denyMembers",
			Heartbeat:       Heartbeat{D: "registry-pass:heartbeat"},
		},
		Grants: Grants{
			File:               "/etc/registry-pass/grants.yaml",
			Reload:             "sighup",
			NamePattern:        `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`,
			AutoReserve:        true,
			StaticUserCacheTTL: Duration(time.Minute),
		},
		RateLimit: RateLimit{
			Enabled:       true,
			PerIP:         Rate{N: 300, Per: time.Minute},
			PerPubkey:     Rate{N: 120, Per: time.Minute},
			PerStaticUser: Rate{N: 600, Per: time.Minute},
			FailuresPerIP: Rate{N: 30, Per: time.Minute},
			Burst:         20,
		},
		Logging: Logging{Level: "info", Format: "json", LogGranted: true},
	}
}

// Relay source defaults, applied to each relay source after loading.
const (
	DefaultAuthWait      = 5 * time.Second
	DefaultResync        = 10 * time.Minute
	DefaultPageSize      = 500
	DefaultDedupeSize    = 50000
	DefaultSignerTimeout = 30 * time.Second
	DefaultPollInterval  = 30 * time.Second
	DefaultHTTPInterval  = 60 * time.Second
	DefaultHTTPTimeout   = 10 * time.Second
)

func (c *Config) applySourceDefaults() {
	for i := range c.Membership.Sources {
		s := &c.Membership.Sources[i]
		switch {
		case s.Relay != nil:
			r := s.Relay
			setDur(&r.AuthWait, DefaultAuthWait)
			setDur(&r.Resync, DefaultResync)
			if r.PageSize == 0 {
				r.PageSize = DefaultPageSize
			}
			if r.DedupeSize == 0 {
				r.DedupeSize = DefaultDedupeSize
			}
			if r.Reader != nil {
				setDur(&r.Reader.SignerTimeout, DefaultSignerTimeout)
			}
		case s.File != nil:
			setDur(&s.File.PollInterval, DefaultPollInterval)
		case s.HTTP != nil:
			setDur(&s.HTTP.Interval, DefaultHTTPInterval)
			setDur(&s.HTTP.Timeout, DefaultHTTPTimeout)
		}
	}
}

func setDur(d *Duration, def time.Duration) {
	if *d == 0 {
		*d = Duration(def)
	}
}
