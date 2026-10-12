package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stubRegistry serves one tagged image: alice/app:v1 with a 2048-byte layer.
func stubRegistry(t *testing.T) string {
	const manifest = `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",` +
		`"config":{"digest":"sha256:c0"},"layers":[{"digest":"sha256:a1"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			http.Error(w, "no token", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v2/_catalog":
			w.Write([]byte(`{"repositories":["alice/app"]}`))
		case "/v2/alice/app/tags/list":
			w.Write([]byte(`{"tags":["v1"]}`))
		case "/v2/alice/app/manifests/v1", "/v2/alice/app/manifests/sha256:m1":
			w.Header().Set("Docker-Content-Digest", "sha256:m1")
			w.Write([]byte(manifest))
		case "/v2/alice/app/blobs/sha256:c0":
			w.Header().Set("Content-Length", "100")
		case "/v2/alice/app/blobs/sha256:a1":
			w.Header().Set("Content-Length", "2048")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func withQuota(t *testing.T, s setup, registry string) {
	t.Helper()
	tok := filepath.Join(s.dir, "events.token")
	os.WriteFile(tok, []byte("events-secret\n"), 0o600)
	cfg, _ := os.ReadFile(s.config)
	cfg = append(cfg, []byte("quota: {enabled: true, registry: "+registry+", eventsTokenFile: "+tok+
		", store: "+filepath.Join(s.dir, "data", "quota.db")+", rebuildInterval: 0s}\n")...)
	os.WriteFile(s.config, cfg, 0o600)
}

func TestQuotaRebuildCommand(t *testing.T) {
	s := newSetup(t, "none")
	if code, _, e := runCmd(t, context.Background(), "--config", s.config, "quota", "rebuild"); code != 1 || !strings.Contains(e, "off") {
		t.Fatalf("rebuild with the module off: %d %s", code, e)
	}
	if code, _, _ := runCmd(t, context.Background(), "--config", s.config, "quota"); code != 2 {
		t.Fatal("quota without subcommand")
	}
	withQuota(t, s, stubRegistry(t))

	// No server: the command opens the store itself.
	code, out, e := runCmd(t, context.Background(), "--config", s.config, "quota", "rebuild")
	if code != 0 || !strings.Contains(out, "alice") || !strings.Contains(out, "rebuilt 1 repositories") {
		t.Fatalf("offline rebuild: %d %s %s", code, out, e)
	}

	// A running server holds the store: the command asks it.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- run(ctx, []string{"--config", s.config}, nil, &bytes.Buffer{}, &bytes.Buffer{}) }()
	waitHTTP(t, "http://"+s.admin+"/readyz")
	code, out, e = runCmd(t, context.Background(), "--config", s.config, "quota", "rebuild")
	if code != 0 || !strings.Contains(out, "2.2KiB") || !strings.Contains(out, "3 blobs") {
		t.Fatalf("rebuild through the server: %d %s %s", code, out, e)
	}
	code, _, e = runCmd(t, context.Background(), "--config", s.config, "quota", "rebuild", "--url", "http://"+s.admin)
	if code != 1 {
		t.Fatalf("rebuild against the wrong listener succeeded: %s", e)
	}
	cancel()
	if c := <-done; c != 0 {
		t.Fatalf("serve exited %d", c)
	}
}
