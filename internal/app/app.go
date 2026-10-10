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
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/ohstr/registry-pass/internal/config"
	"github.com/ohstr/registry-pass/internal/grants"
	"github.com/ohstr/registry-pass/internal/login"
	"github.com/ohstr/registry-pass/internal/membership"
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
	Log     *slog.Logger

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
	a.Server, err = server.New(server.Deps{
		Config: cfg, Verifier: verifier, Issuer: iss, Policy: policy, Store: a.Store, Sources: srcs, Log: log,
	})
	if err != nil {
		a.Close()
		return nil, err
	}
	return a, nil
}

func (a *App) buildMembership(ctx context.Context) error {
	m := a.Config.Membership
	a.Store = membership.New(membership.Options{
		Authorities: m.Authorities, Kind: m.Kind, DPrefix: m.DPrefix, NameMismatch: m.NameMismatch,
		Resolve: m.Resolve, FutureSkew: m.FutureSkew.D(), HonorDeletions: m.HonorDeletions,
		DuplicatePubkey: m.DuplicatePubkey, StaleAfter: m.StaleAfter.D(), OnStale: m.OnStale,
		Heartbeat: m.Heartbeat.Enabled, HeartbeatD: m.Heartbeat.D,
	})
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
				_ = a.ReloadGrants()
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
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-w.Events:
				if !ok {
					return
				}
				if filepath.Clean(ev.Name) == filepath.Clean(path) || filepath.Base(ev.Name) == "..data" {
					_ = a.ReloadGrants()
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
