// Command janitor is a safe, reversible workspace hygiene tool for developer
// and AI-agent machines.
//
// It inventories workspace state locally, applies deterministic safety
// guards, and produces reviewable plans. It never mutates anything without an
// explicit, confirmed apply step.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/gitmoot/workspace-janitor/internal/cli"
	"github.com/gitmoot/workspace-janitor/internal/config"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	code := cli.Run(ctx, cli.Options{
		Args:   os.Args[1:],
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Lookup: config.SystemLookup(),
	})
	os.Exit(int(code))
}
