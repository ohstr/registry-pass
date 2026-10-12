package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ohstr/registry-pass/internal/testkit"
)

func TestQuotaOffByDefault(t *testing.T) {
	cfg, _, err := Load(minimal(t, ""), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Quota.Enabled || cfg.Quota.Default.Bytes() != 10<<30 || cfg.Quota.DPrefix != "quota:" {
		t.Fatalf("quota defaults: %+v", cfg.Quota)
	}
}

func TestQuotaConfig(t *testing.T) {
	alice := testkit.NewKey("alice")
	p := minimal(t, `quota:
  enabled: true
  default: 2GiB
  perName: {alice: 50GiB}
  exempt: [ci, `+alice.Npub+`]
  registry: http://registry:5000
  eventsTokenFile: /run/secrets/events.token
`)
	cfg, origins, err := Load(p, []string{"REGISTRY_PASS_QUOTA__DEFAULT=3GiB"})
	if err != nil {
		t.Fatal(err)
	}
	q := cfg.Quota
	if q.Default.Bytes() != 3<<30 || q.PerName["alice"].Bytes() != 50<<30 || origins.Of("quota.default") != FromEnv {
		t.Fatalf("quota: %+v", q)
	}
	if q.Exempt[0] != "ci" || q.Exempt[1] != alice.Pub {
		t.Fatalf("exempt keys not normalized: %v", q.Exempt)
	}
	if cfg.QuotaService() != "registry.example" {
		t.Fatalf("service: %q", cfg.QuotaService())
	}

	_, _, err = Load(minimal(t, `quota:
  enabled: true
  default: 0
  perName: {Bad_Name: 1GiB, bob: 0}
  exempt: ["not a name"]
  registry: ftp://x
  dPrefix: "member:x"
`), nil)
	msg := problems(t, err)
	for _, want := range []string{"quota.default", `quota.perName: "Bad_Name"`, "quota.perName[bob]", "quota.exempt[0]",
		"quota.registry", "quota.eventsTokenFile", "quota.dPrefix"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in:\n%s", want, msg)
		}
	}
	if _, _, err := Load(minimal(t, "quota:\n  default: 5XB\n"), nil); err == nil {
		t.Error("bad size accepted")
	}
}

func TestStorageQuotaExampleIsValid(t *testing.T) {
	data, err := os.ReadFile("../../examples/storage-quota/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg, _, err := Load(minimal(t, string(data)), nil)
	if err != nil {
		t.Fatalf("examples/storage-quota/config.yaml: %v", err)
	}
	if !cfg.Quota.Enabled || len(cfg.Quota.Exempt) != 1 {
		t.Fatalf("quota: %+v", cfg.Quota)
	}
}

func TestQuotaCheckFiles(t *testing.T) {
	dir := t.TempDir()
	tok := filepath.Join(dir, "events.token")
	cfg := Default()
	cfg.Quota = Quota{Enabled: true, EventsTokenFile: tok}
	if err := cfg.CheckFiles(); err == nil || !strings.Contains(err.Error(), "quota.eventsTokenFile") {
		t.Fatalf("missing token file: %v", err)
	}
	os.WriteFile(tok, []byte("  \n"), 0o600)
	if err := cfg.CheckFiles(); err == nil || !strings.Contains(err.Error(), "quota.eventsTokenFile") {
		t.Fatal("empty token file accepted")
	}
	os.WriteFile(tok, []byte("s3cret\n"), 0o600)
	if got, err := ReadSecret(tok); err != nil || got != "s3cret" {
		t.Fatalf("ReadSecret: %q %v", got, err)
	}
}
