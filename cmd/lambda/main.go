// Command lambda runs the control plane as an AWS Lambda function
// (provided.al2023, built as "bootstrap") behind an API Gateway HTTP API or a
// function URL. It serves the same routes as cmd/server, with the same
// configuration; settings given as SSM parameter ARNs are read at start.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/aws/aws-lambda-go/lambda"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/app"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/config"
)

func main() {
	h, err := setup(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	lambda.Start(h.invoke)
}

// setup runs once per Lambda instance, in its init phase.
func setup(ctx context.Context) (*handler, error) {
	cfg, err := config.LoadControlPlane(ctx)
	if err != nil {
		return nil, err
	}
	logger := cfg.Logging.Logger(os.Stdout).With("component", "control-plane", "env", cfg.EnvName, "runtime", "lambda")
	slog.SetDefault(logger)
	next, err := app.NewControlPlane(ctx, cfg, logger)
	if err != nil {
		return nil, err
	}
	return &handler{next: next, logger: logger}, nil
}
