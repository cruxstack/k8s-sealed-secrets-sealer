// Command mock-ssm runs the SSM Parameter Store mock for the local stack,
// where the control plane keeps its GitHub App's credentials. It is a
// development tool and is never released.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/httpserver"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/mockssm"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("component", "mock-ssm")
	// MOCK_SSM_SEED names a JSON file of parameters, name to value, that
	// the mock starts with
	seed := map[string]string{}
	if path := os.Getenv("MOCK_SSM_SEED"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to read MOCK_SSM_SEED: %w", err)
		}
		if len(b) > 0 {
			if err := json.Unmarshal(b, &seed); err != nil {
				return fmt.Errorf("failed to read MOCK_SSM_SEED: %w", err)
			}
		}
	}
	addr := os.Getenv("MOCK_SSM_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	logger.Info("seeded", "parameters", len(seed))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return httpserver.Serve(ctx, addr, mockssm.New(seed).Handler(), logger)
}
