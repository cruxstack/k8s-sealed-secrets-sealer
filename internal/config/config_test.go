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

func controlPlaneEnv(extra map[string]string) map[string]string {
	vars := map[string]string{
		"APP_ENV_NAME":          "dev",
		"APP_PUBLIC_URL":        "https://sealer.dev.example.com/",
		"APP_REGISTRY_FILE":     "/etc/sealer/registry.yaml",
		"APP_AGENT_SESSION_KEY": strings.Repeat("k", 32),
		"APP_DYNAMODB_TABLE":    "sealer",
	}
	for k, v := range extra {
		vars[k] = v
	}
	return vars
}

func agentEnv(extra map[string]string) map[string]string {
	vars := map[string]string{
		"APP_CONTROLLER_NAMESPACE": "sealed-secrets",
		"APP_CONTROL_PLANE_URL":    "https://sealer.dev.example.com",
	}
	for k, v := range extra {
		vars[k] = v
	}
	return vars
}

func TestLoadControlPlane_Defaults(t *testing.T) {
	cfg, err := loadControlPlane(env(controlPlaneEnv(nil)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.HTTPAddr != ":8080" || cfg.Logging.Level != slog.LevelInfo || cfg.Logging.Format != "json" {
		t.Errorf("cfg = %+v", cfg)
	}
	if cfg.PublicURL != "https://sealer.dev.example.com" || cfg.AgentAudience != cfg.PublicURL {
		t.Errorf("PublicURL = %q, AgentAudience = %q", cfg.PublicURL, cfg.AgentAudience)
	}
	if cfg.AdminToken != "" || cfg.DynamoDBCreateTable {
		t.Errorf("admin and create-table must be off by default: %+v", cfg)
	}
}

func TestLoadControlPlane_ReportsEveryProblem(t *testing.T) {
	_, err := loadControlPlane(env(map[string]string{
		"APP_PUBLIC_URL":            "ftp://x",
		"APP_AGENT_SESSION_KEY":     "short",
		"APP_ADMIN_TOKEN":           "short",
		"APP_DYNAMODB_CREATE_TABLE": "true",
	}))
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{
		"APP_ENV_NAME is required",
		"APP_PUBLIC_URL must be an absolute http(s) URL",
		"APP_REGISTRY_FILE is required",
		"APP_AGENT_SESSION_KEY must be at least 32 bytes",
		"APP_ADMIN_TOKEN must be at least 32 bytes",
		"APP_DYNAMODB_TABLE is required",
		"requires APP_DYNAMODB_ENDPOINT",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q:\n%v", want, err)
		}
	}
	if strings.Contains(err.Error(), "short") {
		t.Error("error leaks a secret value")
	}
}

func TestLoadAgent_Defaults(t *testing.T) {
	cfg, err := loadAgent(env(agentEnv(nil)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ControllerName != "sealed-secrets-controller" || cfg.ControllerDeployment != cfg.ControllerName {
		t.Errorf("controller = %q / %q", cfg.ControllerName, cfg.ControllerDeployment)
	}
	if cfg.CheckInInterval != 15*time.Second || cfg.HTTPAddr != ":8081" || cfg.TokenFile != DefaultTokenFile {
		t.Errorf("cfg = %+v", cfg)
	}
	if len(cfg.Capabilities) != 1 || !cfg.HasCapability("seal") {
		t.Errorf("Capabilities = %v, want [seal]", cfg.Capabilities)
	}
}

func TestLoadAgent_RequiresHTTPSUnlessAllowed(t *testing.T) {
	plain := agentEnv(map[string]string{"APP_CONTROL_PLANE_URL": "http://sealer.local"})
	if _, err := loadAgent(env(plain)); err == nil || !strings.Contains(err.Error(), "absolute https URL") {
		t.Fatalf("plain http accepted: %v", err)
	}
	plain["APP_ALLOW_INSECURE_CONTROL_PLANE"] = "true"
	if _, err := loadAgent(env(plain)); err != nil {
		t.Fatalf("explicitly allowed http rejected: %v", err)
	}
}

func TestLoadAgent_ReportsEveryProblem(t *testing.T) {
	_, err := loadAgent(env(map[string]string{
		"APP_CONTROLLER_NAME":  "Not_A_Label",
		"APP_CHECKIN_INTERVAL": "1s",
		"APP_CAPABILITIES":     "seal,root",
		"APP_LOG_LEVEL":        "loud",
		"APP_LOG_FORMAT":       "xml",
	}))
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{
		"APP_CONTROLLER_NAMESPACE is required",
		"APP_CONTROLLER_NAME must be a DNS-1123 label",
		"APP_CONTROL_PLANE_URL is required",
		"APP_CHECKIN_INTERVAL must be between",
		`unknown capability "root"`,
		"APP_LOG_LEVEL must be",
		"APP_LOG_FORMAT must be",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q:\n%v", want, err)
		}
	}
}

func TestLoadAgent_Capabilities(t *testing.T) {
	cfg, err := loadAgent(env(agentEnv(map[string]string{"APP_CAPABILITIES": " seal, keys,keys ,renewal"})))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(cfg.Capabilities, ","); got != "seal,keys,renewal" {
		t.Errorf("Capabilities = %q", got)
	}
}

func TestLoadAgent_IdentityMode(t *testing.T) {
	cfg, err := loadAgent(env(agentEnv(nil)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IdentityMode != "k8s-oidc" || cfg.IdentityAudience != "https://sealer.dev.example.com" {
		t.Errorf("defaults: mode=%q audience=%q", cfg.IdentityMode, cfg.IdentityAudience)
	}
	cfg, err = loadAgent(env(agentEnv(map[string]string{"APP_IDENTITY_MODE": "aws-sts", "APP_AWS_STS_REGION": "us-east-2"})))
	if err != nil || cfg.IdentityMode != "aws-sts" || cfg.AWSSTSRegion != "us-east-2" {
		t.Fatalf("aws mode: %+v %v", cfg, err)
	}
	if _, err := loadAgent(env(agentEnv(map[string]string{"APP_IDENTITY_MODE": "password"}))); err == nil || !strings.Contains(err.Error(), "APP_IDENTITY_MODE") {
		t.Fatalf("unknown mode: %v", err)
	}
}

func TestLoadControlPlane_STSHosts(t *testing.T) {
	cfg, err := loadControlPlane(env(controlPlaneEnv(map[string]string{"APP_AWS_STS_HOSTS": "sts.us-east-1.amazonaws.com, sts.vpce.example.com:443"})))
	if err != nil || len(cfg.AWSSTSHosts) != 2 || cfg.AWSSTSHosts[1] != "sts.vpce.example.com:443" {
		t.Fatalf("hosts = %v, %v", cfg.AWSSTSHosts, err)
	}
	if _, err := loadControlPlane(env(controlPlaneEnv(map[string]string{"APP_AWS_STS_HOSTS": "https://sts.amazonaws.com/"}))); err == nil {
		t.Fatal("a URL was accepted as a host")
	}
}
