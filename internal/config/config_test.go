package config

import (
	"log/slog"
	"strings"
	"testing"
	"time"
)

func env(vars map[string]string) lookupFunc {
	return func(key string) (string, bool) {
		v, ok := vars[key]
		return v, ok
	}
}

func TestLoadControlPlane_Defaults(t *testing.T) {
	cfg, err := loadControlPlane(env(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.HTTPAddr != ":8080" {
		t.Errorf("HTTPAddr = %q, want :8080", cfg.HTTPAddr)
	}
	if cfg.Logging.Level != slog.LevelInfo || cfg.Logging.Format != "json" {
		t.Errorf("Logging = %+v, want info/json", cfg.Logging)
	}
}

func TestLoadAgent_Defaults(t *testing.T) {
	cfg, err := loadAgent(env(map[string]string{"APP_CONTROLLER_NAMESPACE": "sealed-secrets"}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ControllerName != "sealed-secrets-controller" {
		t.Errorf("ControllerName = %q", cfg.ControllerName)
	}
	if cfg.InventoryInterval != time.Minute {
		t.Errorf("InventoryInterval = %s, want 1m", cfg.InventoryInterval)
	}
	if cfg.HTTPAddr != ":8081" {
		t.Errorf("HTTPAddr = %q, want :8081", cfg.HTTPAddr)
	}
}

func TestLoadAgent_ReportsEveryProblem(t *testing.T) {
	_, err := loadAgent(env(map[string]string{
		"APP_CONTROLLER_NAME":    "Not_A_Label",
		"APP_INVENTORY_INTERVAL": "1s",
		"APP_LOG_LEVEL":          "loud",
		"APP_LOG_FORMAT":         "xml",
	}))
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{
		"APP_CONTROLLER_NAMESPACE is required",
		"APP_CONTROLLER_NAME must be a DNS-1123 label",
		"APP_INVENTORY_INTERVAL must be between",
		"APP_LOG_LEVEL must be",
		"APP_LOG_FORMAT must be",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q:\n%v", want, err)
		}
	}
}

func TestLoadAgent_RejectsUnparsableDuration(t *testing.T) {
	_, err := loadAgent(env(map[string]string{
		"APP_CONTROLLER_NAMESPACE": "sealed-secrets",
		"APP_INVENTORY_INTERVAL":   "soon",
	}))
	if err == nil || !strings.Contains(err.Error(), "must be a duration") {
		t.Fatalf("expected a duration error, got %v", err)
	}
}
