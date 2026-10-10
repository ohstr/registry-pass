// Command docker-credential-registry-pass is a Docker credential helper that
// logs in to registry-pass with a signed Nostr event.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/ohstr/registry-pass/internal/helper"
)

var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Getenv(helper.EnvConfig), os.Stdin, os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, configPath string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: docker-credential-registry-pass <get|store|erase|list|version>")
		return 2
	}
	h := &helper.Helper{Config: &helper.Config{}}
	if args[0] == "get" {
		if configPath == "" {
			configPath = helper.DefaultConfigPath()
		}
		cfg, err := helper.LoadConfig(configPath)
		if err != nil {
			fmt.Fprintln(stdout, err)
			return 1
		}
		h.Config = cfg
	}
	return h.Run(ctx, args[0], stdin, stdout, stderr, version)
}
