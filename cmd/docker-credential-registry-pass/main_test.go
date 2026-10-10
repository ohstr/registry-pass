package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ohstr/registry-pass/internal/testkit"
)

func TestRun(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), nil, "", strings.NewReader(""), &out, &errOut); code != 2 {
		t.Fatal("no action")
	}
	if code := run(context.Background(), []string{"get"}, filepath.Join(t.TempDir(), "none"), strings.NewReader("r\n"), &out, &errOut); code != 1 {
		t.Fatal("missing config")
	}
	out.Reset()
	if code := run(context.Background(), []string{"version"}, "", strings.NewReader(""), &out, &errOut); code != 0 || strings.TrimSpace(out.String()) != "dev" {
		t.Fatal("version")
	}

	dir := t.TempDir()
	k := testkit.NewKey("alice")
	keyPath := filepath.Join(dir, "key")
	os.WriteFile(keyPath, []byte(k.Nsec), 0o600)
	cfg := filepath.Join(dir, "helper.yaml")
	os.WriteFile(cfg, []byte("cacheDir: "+filepath.Join(dir, "cache")+"\nregistries:\n  registry.example:\n    realm: https://pass.example/token\n    signer: file://"+keyPath+"\n"), 0o600)
	out.Reset()
	if code := run(context.Background(), []string{"get"}, cfg, strings.NewReader("registry.example\n"), &out, &errOut); code != 0 || !strings.Contains(out.String(), k.Npub) {
		t.Fatalf("get: %s", out.String())
	}
}
