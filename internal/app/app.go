// Package app wires a validated configuration into a running server: it
// loads secrets, builds the membership sources and reloads grants.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/ohstr/nmilat/nip19"
	"github.com/ohstr/registry-pass/internal/config"
	"github.com/ohstr/registry-pass/internal/grants"
	"github.com/ohstr/registry-pass/internal/login"
	"github.com/ohstr/registry-pass/internal/membership"
	"github.com/ohstr/registry-pass/internal/quota"
	"github.com/ohstr/registry-pass/internal/server"
	"github.com/ohstr/registry-pass/internal/token"
)

// maxPEMSize bounds key and certificate files.
const maxPEMSize = 1 << 20

// App is a built registry-pass.
type App struct {
	Config  *config.Config
	Server  *server.Server
	Store   *membership.Store
	Sources []membership.Source
	Quota   *quota.Module // nil when the quota module is off
	Log     *slog.Logger

	// ConfigPath and Environ re-read the quota limits on reload; an empty
	// path keeps the limits the app was built with.
	ConfigPath string
	Environ    []string

	closers []func()
}

// NewLogger returns the logger the logging settings describe.
func NewLogger(c config.Logging, w io.Writer) *slog.Logger {
	var level slog.Level
	switch c.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	if c.Format == "text" {
		return slog.New(slog.NewTextHandler(w, opts))
	}
	return slog.New(slog.NewJSONHandler(w, opts))
}

// LoadGrants reads and compiles the grants file.
func LoadGrants(cfg *config.Config) (*grants.Policy, error) {
	data, err := config.ReadFileLimited(cfg.Grants.File, maxPEMSize)
	if err != nil {
		return nil, fmt.Errorf("grants: %w", err)
	}
	return grants.Parse(data, grants.Options{NamePattern: cfg.Grants.NamePattern, AutoReserve: cfg.Grants.AutoReserve})
}

// NewIssuer loads the signing key and certificate.
func NewIssuer(cfg *config.Config) (*token.Issuer, error) {
	t := cfg.Token
	key, err := config.ReadFileLimited(t.SigningKeyFile, maxPEMSize)
	if err != nil {
		return nil, fmt.Errorf("token.signingKeyFile: %w", err)
	}
	cert, err := config.ReadFileLimited(t.CertificateFile, maxPEMSize)
	if err != nil {
		return nil, fmt.Errorf("token.certificateFile: %w", err)
	}
	var chain []byte
	if t.ChainFile != "" {
		if chain, err = config.ReadFileLimited(t.ChainFile, maxPEMSize); err != nil {
			return nil, fmt.Errorf("token.chainFile: %w", err)
		}
	}
	iss, err := token.New(key, cert, chain, token.Options{Issuer: cfg.Issuer, Algorithm: t.Algorithm, X5C: t.X5C, KID: t.KID})
	if err != nil {
		return nil, fmt.Errorf("token: %w", err)
	}
	return iss, nil
}

// Build constructs the server and its sources; Run starts them.
func Build(ctx context.Context, cfg *config.Config, log *slog.Logger) (*App, error) {
	a := &App{Config: cfg, Log: log}
	iss, err := NewIssuer(cfg)
	if err != nil {
		return nil, err
	}
	if left := time.Until(iss.NotAfter()); left < cfg.Token.CertExpiryWarning.D() {
		log.Warn("signing certificate expires soon", "notAfter", iss.NotAfter().UTC().Format(time.RFC3339))
	}
	policy, err := LoadGrants(cfg)
	if err != nil {
		return nil, err
	}
	l := cfg.Login
	verifier, err := login.New(login.Options{
		Realm: cfg.Realm, Kind: l.Kind, MaxLifetime: l.MaxLifetime.D(), MinRemaining: l.MinRemaining.D(),
		ClockSkew: l.ClockSkew.D(), RequireServiceTag: l.RequireServiceTag, UsernameFormats: l.UsernameFormats,
		CacheSize: l.CacheSize,
	})
	if err != nil {
		return nil, err
	}
	var srcs []server.Source
	if cfg.Membership.Enabled {
		if err := a.buildMembership(ctx); err != nil {
			a.Close()
			return nil, err
		}
		for _, s := range a.Sources {
			srcs = append(srcs, s)
		}
	}
	if cfg.Quota.Enabled {
		st, err := quota.Open(cfg.Quota.Store, time.Second)
		if err != nil {
			a.Close()
			return nil, fmt.Errorf("quota.store: %w", err)
		}
		a.closers = append(a.closers, func() { st.Close() })
		if a.Quota, err = NewQuota(cfg, iss, st, a.Store, log); err != nil {
			a.Close()
			return nil, err
		}
	}
	a.Server, err = server.New(server.Deps{
		Config: cfg, Verifier: verifier, Issuer: iss, Policy: policy, Store: a.Store, Quota: a.Quota, Sources: srcs, Log: log,
	})
	if err != nil {
		a.Close()
		return nil, err
	}
	return a, nil
}

// QuotaLimits turns the quota settings into limits.
func QuotaLimits(q config.Quota) quota.Limits {
	l := quota.Limits{
		Default: q.Default.Bytes(), PerName: map[string]int64{},
		ExemptNames: map[string]bool{}, ExemptKeys: map[string]bool{},
	}
	for n, sz := range q.PerName {
		l.PerName[n] = sz.Bytes()
	}
	for _, e := range q.Exempt {
		// Validate normalized public keys to lowercase hex.
		if _, err := nip19.ParsePublicKey(e); err == nil && len(e) == 64 {
			l.ExemptKeys[e] = true
		} else {
			l.ExemptNames[e] = true
		}
	}
	return l
}

// NewQuota builds the quota module on an open store. members, when not
// nil, supplies authority-signed quotas.
func NewQuota(cfg *config.Config, iss *token.Issuer, st *quota.Store, members *membership.Store, log *slog.Logger) (*quota.Module, error) {
	q := cfg.Quota
	base, err := url.Parse(strings.TrimSuffix(q.Registry, "/") + "/")
	if err != nil {
		return nil, fmt.Errorf("quota.registry: %w", err)
	}
	client, err := membership.NewHTTPClient(q.RegistryCAFile, q.Timeout.D())
	if err != nil {
		return nil, fmt.Errorf("quota.registryCAFile: %w", err)
	}
	eventsToken, err := config.ReadSecret(q.EventsTokenFile)
	if err != nil {
		return nil, fmt.Errorf("quota.eventsTokenFile: %w", err)
	}
	service, lifetime := cfg.QuotaService(), cfg.Token.Lifetime.D()
	mint := func(access []grants.Access) (string, error) {
		tok, err := iss.Issue(cfg.Issuer, service, access, time.Now().Add(lifetime))
		return tok.Raw, err
	}
	var signed func(string) (int64, bool)
	if members != nil {
		signed = func(name string) (int64, bool) { return members.Snapshot().Quota(name) }
	}
	return quota.New(quota.Options{
		Store: st, Registry: &quota.Registry{Base: base, Client: client, Mint: mint},
		Limits: QuotaLimits(q), Signed: signed, EventsToken: eventsToken,
		RebuildInterval: q.RebuildInterval.D(), Log: log,
	}), nil
}

// ReloadQuota re-reads the quota limits from the config file; an invalid
// file leaves the current limits in force.
func (a *App) ReloadQuota() error {
	if a.Quota == nil || a.ConfigPath == "" {
		return nil
	}
	cfg, _, err := config.Load(a.ConfigPath, a.Environ)
	if err != nil {
		a.Log.Error("quota reload failed; keeping the previous limits", "err", err)
		return err
	}
	a.Quota.SetLimits(QuotaLimits(cfg.Quota))
	a.Log.Info("quota limits reloaded")
	return nil
}

func (a *App) reload() {
	_ = a.ReloadGrants()
	_ = a.ReloadQuota()
}

func (a *App) buildMembership(ctx context.Context) error {
	m := a.Config.Membership
	opts := membership.Options{
		Authorities: m.Authorities, Kind: m.Kind, DPrefix: m.DPrefix, PubkeyField: m.PubkeyField,
		NameMismatch: m.NameMismatch, Resolve: m.Resolve, FutureSkew: m.FutureSkew.D(),
		HonorDeletions: m.HonorDeletions, DuplicatePubkey: m.DuplicatePubkey,
		StaleAfter: m.StaleAfter.D(), OnStale: m.OnStale,
		Heartbeat: m.Heartbeat.Enabled, HeartbeatD: m.Heartbeat.D,
	}
	if a.Config.Quota.Enabled {
		opts.QuotaDPrefix = a.Config.Quota.DPrefix
	}
	a.Store = membership.New(opts)
	for i, sc := range m.Sources {
		src, err := a.buildSource(ctx, sc)
		if err != nil {
			return fmt.Errorf("membership.sources[%d]: %w", i, err)
		}
		a.Sources = append(a.Sources, src)
		a.Store.AddSource(src)
	}
	return nil
}

func (a *App) buildSource(ctx context.Context, sc config.Source) (membership.Source, error) {
	m := a.Config.Membership
	switch {
	case sc.Relay != nil:
		r := sc.Relay
		src := &membership.RelaySource{
			URLs: r.URLs, Kind: m.Kind, Authorities: m.Authorities, Deletions: m.HonorDeletions,
			RequireAuth: r.AuthRequired(), AuthWait: r.AuthWait.D(), Resync: r.Resync.D(),
			PageSize: r.PageSize, DedupeSize: r.DedupeSize, Log: a.Log,
		}
		if r.Reader != nil {
			var material string
			if r.Reader.KeyFile != "" {
				data, err := config.ReadFileLimited(r.Reader.KeyFile, 4096)
				if err != nil {
					return nil, fmt.Errorf("reader key: %w", err)
				}
				material = string(data)
			}
			signer, closeFn, err := membership.NewSigner(ctx, material, r.Reader.Signer, r.Reader.SignerTimeout.D())
			if err != nil {
				return nil, err
			}
			a.closers = append(a.closers, closeFn)
			src.Signer = signer
		}
		return src, nil
	case sc.File != nil:
		return &membership.FileSource{
			Path: sc.File.Path, Watch: sc.File.Watching(), PollInterval: sc.File.PollInterval.D(), Log: a.Log,
		}, nil
	case sc.HTTP != nil:
		h := sc.HTTP
		client, err := membership.NewHTTPClient(h.CAFile, h.Timeout.D())
		if err != nil {
			return nil, err
		}
		headers := h.Headers
		return &membership.HTTPSource{
			URL: h.URL, Interval: h.Interval.D(), Timeout: h.Timeout.D(), Client: client, Log: a.Log,
			Headers: func() (http.Header, error) {
				out := http.Header{}
				for k, v := range headers {
					val, _, err := config.ResolveFileRef(v, true)
					if err != nil {
						return nil, fmt.Errorf("header %s: %w", k, err)
					}
					out.Set(k, val)
				}
				return out, nil
			},
		}, nil
	}
	return nil, errors.New("no source type")
}

// ReloadGrants re-reads the grants file; an invalid file leaves the
// current grants in force.
func (a *App) ReloadGrants() error {
	p, err := LoadGrants(a.Config)
	a.Server.Reloaded(err == nil)
	if err != nil {
		a.Log.Error("grants reload failed; keeping the previous grants", "err", err)
		return err
	}
	a.Server.SetPolicy(p)
	a.Log.Info("grants reloaded")
	return nil
}

// Run starts the sources, the grants reloader and the server, and blocks
// until ctx ends.
func (a *App) Run(ctx context.Context, l server.Listeners) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	for _, src := range a.Sources {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := src.Run(ctx, a.Store); err != nil {
				a.Log.Error("membership source stopped", "source", src.Name(), "err", err)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		a.watchGrants(ctx)
	}()
	if a.Quota != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.Quota.Run(ctx)
		}()
	}
	a.Log.Info("registry-pass started", "listen", l.Main.Addr().String(), "services", a.Config.Services,
		"membership", a.Config.Membership.Enabled, "sources", len(a.Sources))
	err := a.Server.Run(ctx, l)
	cancel()
	wg.Wait()
	a.Close()
	return err
}

func (a *App) watchGrants(ctx context.Context) {
	switch a.Config.Grants.Reload {
	case "sighup":
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGHUP)
		defer signal.Stop(ch)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ch:
				a.reload()
			}
		}
	case "watch":
		w, err := fsnotify.NewWatcher()
		if err != nil {
			a.Log.Error("grants watch unavailable", "err", err)
			return
		}
		defer w.Close()
		path := a.Config.Grants.File
		if err := w.Add(filepath.Dir(path)); err != nil {
			a.Log.Error("grants watch unavailable", "err", err)
			return
		}
		// The quota limits live in the config file: watch it too.
		cfgPath := ""
		if a.Quota != nil && a.ConfigPath != "" {
			cfgPath = a.ConfigPath
			if filepath.Dir(cfgPath) != filepath.Dir(path) {
				if err := w.Add(filepath.Dir(cfgPath)); err != nil {
					a.Log.Error("config watch unavailable", "err", err)
				}
			}
		}
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-w.Events:
				if !ok {
					return
				}
				name := filepath.Clean(ev.Name)
				switch {
				case filepath.Base(ev.Name) == "..data":
					a.reload()
				case name == filepath.Clean(path):
					_ = a.ReloadGrants()
				case cfgPath != "" && name == filepath.Clean(cfgPath):
					_ = a.ReloadQuota()
				}
			}
		}
	}
}

// Close releases signers.
func (a *App) Close() {
	for _, c := range a.closers {
		c()
	}
	a.closers = nil
}
