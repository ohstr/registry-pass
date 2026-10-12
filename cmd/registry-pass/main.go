// Command registry-pass is a token service that lets OCI registry clients
// log in with a signed Nostr event.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ohstr/registry-pass/internal/app"
	"github.com/ohstr/registry-pass/internal/config"
	"github.com/ohstr/registry-pass/internal/token"
)

// version is set at build time with -ldflags "-X main.version=…".
var version = "dev"

const usage = `usage: registry-pass [--config FILE] <command>

commands:
  serve            run the token service (default)
  config check     validate the configuration and the files it names
  config print     show the effective configuration and where each value came from
  config env       list every environment override
  keygen           create a signing key and self-signed certificate
  quota rebuild    recount every namespace's storage from the registry
  skills           list, show or install the built-in agent skills
  version          print the version

The config file defaults to $REGISTRY_PASS_CONFIG or /etc/registry-pass/config.yaml.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Environ(), os.Stdout, os.Stderr))
}

func run(ctx context.Context, args, environ []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("registry-pass", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	configPath := fs.String("config", defaultConfigPath(environ), "config file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	cmd := "serve"
	if len(rest) > 0 {
		cmd, rest = rest[0], rest[1:]
	}
	env := withoutConfigVar(environ)

	switch cmd {
	case "serve":
		return serve(ctx, *configPath, env, stderr)
	case "config":
		if len(rest) != 1 {
			fmt.Fprint(stderr, usage)
			return 2
		}
		return configCmd(rest[0], *configPath, env, stdout, stderr)
	case "keygen":
		return keygen(rest, stdout, stderr)
	case "quota":
		return quotaCmd(ctx, rest, *configPath, env, stdout, stderr)
	case "skills":
		return skillsCmd(rest, stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	fmt.Fprintf(stderr, "unknown command %q\n%s", cmd, usage)
	return 2
}

func defaultConfigPath(environ []string) string {
	for _, kv := range environ {
		if v, ok := strings.CutPrefix(kv, "REGISTRY_PASS_CONFIG="); ok && v != "" {
			return v
		}
	}
	return "/etc/registry-pass/config.yaml"
}

// withoutConfigVar drops REGISTRY_PASS_CONFIG, which names the file and is
// not a setting.
func withoutConfigVar(environ []string) []string {
	out := make([]string, 0, len(environ))
	for _, kv := range environ {
		if !strings.HasPrefix(kv, "REGISTRY_PASS_CONFIG=") {
			out = append(out, kv)
		}
	}
	return out
}

func serve(ctx context.Context, path string, env []string, stderr io.Writer) int {
	cfg, _, err := config.Load(path, env)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	log := app.NewLogger(cfg.Logging, stderr)
	a, err := app.Build(ctx, cfg, log)
	if err != nil {
		log.Error("startup failed", "err", err)
		return 1
	}
	a.ConfigPath, a.Environ = path, env
	l, err := a.Server.Listen()
	if err != nil {
		a.Close()
		log.Error("listen failed", "err", err)
		return 1
	}
	if err := a.Run(ctx, l); err != nil && !errors.Is(err, context.Canceled) {
		log.Error("server stopped", "err", err)
		return 1
	}
	return 0
}

func configCmd(sub, path string, env []string, stdout, stderr io.Writer) int {
	if sub == "env" {
		for _, n := range config.EnvNames() {
			fmt.Fprintln(stdout, n)
		}
		return 0
	}
	cfg, origins, err := config.Load(path, env)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	switch sub {
	case "check":
		if err := cfg.CheckFiles(); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if _, err := app.NewIssuer(cfg); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if _, err := app.LoadGrants(cfg); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintln(stdout, "configuration OK")
		return 0
	case "print":
		if err := config.Print(stdout, cfg, origins); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stderr, "unknown config command %q\n", sub)
	return 2
}

func keygen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	alg := fs.String("alg", "ES256", "ES256 | ES384 | RS256")
	cn := fs.String("cn", "registry-pass", "certificate common name")
	days := fs.Int("days", 365, "certificate validity in days")
	keyOut := fs.String("key-out", "pass.key", "private key output file (created 0600)")
	certOut := fs.String("cert-out", "pass.crt", "certificate output file (give this one to the registry)")
	force := fs.Bool("force", false, "overwrite existing files")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *days < 1 {
		fmt.Fprintln(stderr, "keygen: --days must be at least 1")
		return 2
	}
	keyPEM, certPEM, err := token.Generate(*alg, *cn, time.Duration(*days)*24*time.Hour)
	if err != nil {
		fmt.Fprintln(stderr, "keygen:", err)
		return 1
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if *force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	for _, f := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{{*keyOut, keyPEM, 0o600}, {*certOut, certPEM, 0o644}} {
		if err := os.MkdirAll(filepath.Dir(f.path), 0o755); err != nil {
			fmt.Fprintln(stderr, "keygen:", err)
			return 1
		}
		fh, err := os.OpenFile(f.path, flags, f.mode)
		if err != nil {
			fmt.Fprintln(stderr, "keygen:", err)
			return 1
		}
		_, werr := fh.Write(f.data)
		cerr := fh.Close()
		if werr != nil || cerr != nil {
			fmt.Fprintln(stderr, "keygen:", errors.Join(werr, cerr))
			return 1
		}
	}
	fmt.Fprintf(stdout, "wrote %s (keep secret) and %s (registry rootcertbundle)\n", *keyOut, *certOut)
	return 0
}
