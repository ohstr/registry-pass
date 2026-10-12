package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"time"

	"github.com/ohstr/registry-pass/internal/app"
	"github.com/ohstr/registry-pass/internal/bytesize"
	"github.com/ohstr/registry-pass/internal/config"
	"github.com/ohstr/registry-pass/internal/quota"
	"github.com/ohstr/registry-pass/internal/server"
)

func quotaCmd(ctx context.Context, args []string, path string, env []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "rebuild" {
		fmt.Fprintln(stderr, "usage: registry-pass quota rebuild [--url URL]")
		return 2
	}
	fs := flag.NewFlagSet("quota rebuild", flag.ContinueOnError)
	fs.SetOutput(stderr)
	serverURL := fs.String("url", "", "running registry-pass to ask when it holds the store (default: from server.listen)")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	cfg, _, err := config.Load(path, env)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if !cfg.Quota.Enabled {
		fmt.Fprintln(stderr, "quota rebuild: the quota module is off (quota.enabled)")
		return 1
	}
	sum, err := rebuildOffline(ctx, cfg, stderr)
	if errors.Is(err, quota.ErrLocked) {
		sum, err = rebuildRemote(ctx, cfg, *serverURL)
	}
	if err != nil {
		fmt.Fprintln(stderr, "quota rebuild:", err)
		return 1
	}
	names := make([]string, 0, len(sum.Namespaces))
	for ns := range sum.Namespaces {
		names = append(names, ns)
	}
	sort.Strings(names)
	for _, ns := range names {
		u := sum.Namespaces[ns]
		fmt.Fprintf(stdout, "%-32s %10s %6d blobs\n", ns, bytesize.Format(u.Used), u.Blobs)
	}
	fmt.Fprintf(stdout, "rebuilt %d repositories in %s\n", sum.Repositories, sum.Took)
	return 0
}

// rebuildOffline recounts into the store when no server holds it.
func rebuildOffline(ctx context.Context, cfg *config.Config, stderr io.Writer) (quota.Summary, error) {
	st, err := quota.Open(cfg.Quota.Store, 2*time.Second)
	if err != nil {
		return quota.Summary{}, err
	}
	defer st.Close()
	iss, err := app.NewIssuer(cfg)
	if err != nil {
		return quota.Summary{}, err
	}
	log := app.NewLogger(config.Logging{Level: "warn", Format: "text"}, stderr)
	m, err := app.NewQuota(cfg, iss, st, nil, log)
	if err != nil {
		return quota.Summary{}, err
	}
	return m.Rebuild(ctx)
}

// rebuildRemote asks the running server, which holds the store, to
// recount.
func rebuildRemote(ctx context.Context, cfg *config.Config, target string) (quota.Summary, error) {
	client := &http.Client{}
	if target == "" {
		host, port, err := net.SplitHostPort(cfg.Server.Listen)
		if err != nil {
			return quota.Summary{}, err
		}
		if host == "" || host == "0.0.0.0" || host == "::" {
			host = "127.0.0.1"
		}
		scheme := "http"
		if cfg.Server.TLS.Enabled() {
			// The certificate names the public host, not the loopback.
			scheme = "https"
			client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}} //nolint:gosec
		}
		target = scheme + "://" + net.JoinHostPort(host, port)
	}
	tok, err := config.ReadSecret(cfg.Quota.EventsTokenFile)
	if err != nil {
		return quota.Summary{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target+server.RebuildPath, nil)
	if err != nil {
		return quota.Summary{}, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := client.Do(req)
	if err != nil {
		return quota.Summary{}, fmt.Errorf("the store is held by a running server, and asking it failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return quota.Summary{}, fmt.Errorf("server: %s: %s", resp.Status, body)
	}
	var sum quota.Summary
	return sum, json.NewDecoder(resp.Body).Decode(&sum)
}
