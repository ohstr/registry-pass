package server

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func promHandler(reg *prometheus.Registry) http.Handler {
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
}

// Listeners are the sockets Run serves on; tests pass their own.
type Listeners struct {
	Main  net.Listener
	Admin net.Listener // nil when admin shares Main
}

// Listen opens the configured sockets.
func (s *Server) Listen() (Listeners, error) {
	var l Listeners
	var err error
	if l.Main, err = net.Listen("tcp", s.cfg.Server.Listen); err != nil {
		return l, err
	}
	if s.cfg.Admin.Listen != "" {
		if l.Admin, err = net.Listen("tcp", s.cfg.Admin.Listen); err != nil {
			l.Main.Close()
			return l, err
		}
	}
	return l, nil
}

func (s *Server) httpServer(h http.Handler) *http.Server {
	c := s.cfg.Server
	return &http.Server{
		Handler:           h,
		ReadTimeout:       c.ReadTimeout.D(),
		ReadHeaderTimeout: c.ReadTimeout.D(),
		WriteTimeout:      c.WriteTimeout.D(),
		IdleTimeout:       c.IdleTimeout.D(),
		MaxHeaderBytes:    c.MaxHeaderBytes,
	}
}

// Run serves until ctx ends, then shuts down within shutdownGrace.
func (s *Server) Run(ctx context.Context, l Listeners) error {
	main := s.httpServer(s.Handler())
	servers := []*http.Server{main}
	errc := make(chan error, 2)

	tlsCfg := s.cfg.Server.TLS
	go func() {
		if tlsCfg.Enabled() {
			minV := uint16(tls.VersionTLS12)
			if tlsCfg.MinVersion == "1.3" {
				minV = tls.VersionTLS13
			}
			main.TLSConfig = &tls.Config{MinVersion: minV}
			errc <- main.ServeTLS(l.Main, tlsCfg.CertFile, tlsCfg.KeyFile)
			return
		}
		errc <- main.Serve(l.Main)
	}()
	if l.Admin != nil {
		admin := s.httpServer(s.AdminHandler())
		servers = append(servers, admin)
		go func() { errc <- admin.Serve(l.Admin) }()
	}

	var runErr error
	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			runErr = err
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), s.cfg.Server.ShutdownGrace.D())
	defer cancel()
	for _, srv := range servers {
		if err := srv.Shutdown(shutdown); err != nil && runErr == nil {
			runErr = err
		}
	}
	return runErr
}
