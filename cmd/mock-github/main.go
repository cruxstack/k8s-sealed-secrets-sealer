// Command mock-github runs the GitHub mock for the local stack. It is a
// development tool and is never released.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/golang-jwt/jwt/v5"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/httpserver"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/mockgithub"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("component", "mock-github")
	repos, err := mockgithub.Fixtures()
	if err != nil {
		return err
	}
	app := mockgithub.App{ID: env("MOCK_GITHUB_APP_ID", "1"), InstallationID: 100}
	if pemKey := os.Getenv("MOCK_GITHUB_APP_PUBLIC_KEY"); pemKey != "" {
		key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pemKey))
		if err != nil {
			return fmt.Errorf("failed to read MOCK_GITHUB_APP_PUBLIC_KEY: %w", err)
		}
		app.PublicKey = key
	}
	srv := mockgithub.New(mockgithub.Options{
		ClientID:     env("MOCK_GITHUB_CLIENT_ID", "local-client-id"),
		ClientSecret: env("MOCK_GITHUB_CLIENT_SECRET", "local-client-secret"),
		CallbackURLs: strings.Split(env("MOCK_GITHUB_CALLBACK_URLS", "http://localhost:4100/api/v1/auth/callback"), ","),
		Org:          env("MOCK_GITHUB_ORG", "example-org"),
		Users:        mockgithub.DefaultUsers(),
		App:          app,
		Repos:        repos,
		WebURL:       os.Getenv("MOCK_GITHUB_WEB_URL"),
	})
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return httpserver.Serve(ctx, env("MOCK_GITHUB_ADDR", ":8080"), srv.Handler(), logger)
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
