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
		"APP_ENV_NAME":                   "dev",
		"APP_PUBLIC_URL":                 "https://sealer.dev.example.com/",
		"APP_REGISTRY_FILE":              "/etc/sealer/registry.yaml",
		"APP_AGENT_SESSION_KEY":          strings.Repeat("k", 32),
		"APP_DYNAMODB_TABLE":             "sealer",
		"APP_GITHUB_ORG":                 "example-org",
		"APP_GITHUB_OAUTH_CLIENT_ID":     "client-id",
		"APP_GITHUB_OAUTH_CLIENT_SECRET": "client-secret",
		"APP_USER_SESSION_KEY":           strings.Repeat("u", 32),
		"APP_GITHUB_APP_ID":              "12345",
		"APP_GITHUB_APP_PRIVATE_KEY":     "-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----\n",
		"APP_KMS_TRANSIT_KEY_ID":         "alias/sealer-transit",
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
		"APP_ENV_NAME":             "dev",
		"APP_KMS_TRANSIT_KEY_ID":   "alias/sealer-transit",
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
	if cfg.AdminToken != "" || cfg.AdminTokenKeyChanges || cfg.DynamoDBCreateTable {
		t.Errorf("admin and create-table must be off by default: %+v", cfg)
	}
	token := strings.Repeat("t", MinAdminTokenBytes)
	if cfg, err := loadControlPlane(env(controlPlaneEnv(map[string]string{"APP_ADMIN_TOKEN": token, "APP_ADMIN_TOKEN_KEY_CHANGES": "true"}))); err != nil || !cfg.AdminTokenKeyChanges {
		t.Errorf("admin token key changes = %v, %v", cfg, err)
	}
	if _, err := loadControlPlane(env(controlPlaneEnv(map[string]string{"APP_ADMIN_TOKEN_KEY_CHANGES": "true"}))); err == nil || !strings.Contains(err.Error(), "needs an admin token") {
		t.Errorf("key changes without an admin token = %v", err)
	}
	if cfg.KeyRenewPeriod != 720*time.Hour {
		t.Errorf("KeyRenewPeriod = %s, want 720h", cfg.KeyRenewPeriod)
	}
	if cfg.KMSTransitKeyID != "alias/sealer-transit" || cfg.KMSRegion != "" || cfg.KMSEndpoint != "" {
		t.Errorf("KMS = %q %q %q", cfg.KMSTransitKeyID, cfg.KMSRegion, cfg.KMSEndpoint)
	}
	if cfg.GitHubAppID != "12345" || cfg.GitHubAppInstallationID != 0 || cfg.EnvAnnotation != "k8s-sealed-secrets-sealer/env" ||
		cfg.RegionAnnotation != "k8s-sealed-secrets-sealer/region" || cfg.DiscoveryFileGlobs != nil {
		t.Errorf("cfg = %+v", cfg)
	}
}

func TestLoadControlPlane_GitHubAppAndDiscovery(t *testing.T) {
	cfg, err := loadControlPlane(env(controlPlaneEnv(map[string]string{
		"APP_GITHUB_APP_INSTALLATION_ID": "77",
		"APP_ENV_ANNOTATION":             "acme.io/env",
		"APP_DISCOVERY_FILE_GLOBS":       "*.sealed.yaml, secrets/*/*.yaml",
	})))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GitHubAppInstallationID != 77 || cfg.EnvAnnotation != "acme.io/env" || len(cfg.DiscoveryFileGlobs) != 2 {
		t.Errorf("cfg = %+v", cfg)
	}
	_, err = loadControlPlane(env(controlPlaneEnv(map[string]string{
		"APP_GITHUB_APP_PRIVATE_KEY":     "not a key",
		"APP_GITHUB_APP_INSTALLATION_ID": "-1",
		"APP_REGION_ANNOTATION":          "not a key!",
		"APP_DISCOVERY_FILE_GLOBS":       "[bad",
	})))
	for _, want := range []string{"must be a PEM private key", "APP_GITHUB_APP_INSTALLATION_ID", "APP_REGION_ANNOTATION", "not a valid glob"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
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
		"set exactly one of APP_REGISTRY_FILE and APP_REGISTRY",
		"APP_AGENT_SESSION_KEY must be at least 32 bytes",
		"APP_ADMIN_TOKEN must be at least 32 bytes",
		"APP_DYNAMODB_TABLE is required",
		"requires APP_DYNAMODB_ENDPOINT",
		"APP_KMS_TRANSIT_KEY_ID is required",
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
	if cfg.EnvName != "dev" || cfg.KMSEscrowKeyID != "" || cfg.KMSEndpoint != "" || cfg.KMSTransitKeyID != "alias/sealer-transit" {
		t.Errorf("cfg = %+v", cfg)
	}
}

func TestLoadAgent_SealNeedsTransitKey(t *testing.T) {
	vars := agentEnv(nil)
	delete(vars, "APP_KMS_TRANSIT_KEY_ID")
	if _, err := loadAgent(env(vars)); err == nil || !strings.Contains(err.Error(), "APP_KMS_TRANSIT_KEY_ID is required with the seal capability") {
		t.Fatalf("seal without a transit key: %v", err)
	}
	// an agent that does not seal needs none
	vars["APP_CAPABILITIES"] = "renewal"
	if _, err := loadAgent(env(vars)); err != nil {
		t.Fatal(err)
	}
}

func TestLoadAgent_KeysNeedEscrowKey(t *testing.T) {
	vars := agentEnv(map[string]string{"APP_CAPABILITIES": "seal,keys"})
	if _, err := loadAgent(env(vars)); err == nil || !strings.Contains(err.Error(), "APP_KMS_ESCROW_KEY_ID is required") {
		t.Fatalf("keys without an escrow key: %v", err)
	}
	vars["APP_KMS_ESCROW_KEY_ID"] = "alias/sealer-escrow"
	vars["APP_KMS_ENDPOINT"] = "http://local-kms:8080"
	cfg, err := loadAgent(env(vars))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.KMSEscrowKeyID != "alias/sealer-escrow" || cfg.KMSEndpoint != "http://local-kms:8080" {
		t.Errorf("cfg = %+v", cfg)
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
		"APP_ENV_NAME is required",
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
	cfg, err := loadAgent(env(agentEnv(map[string]string{"APP_CAPABILITIES": " seal, keys,keys ,renewal", "APP_KMS_ESCROW_KEY_ID": "alias/escrow"})))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(cfg.Capabilities, ","); got != "seal,keys,renewal" {
		t.Errorf("Capabilities = %q", got)
	}
}

// An agent can have no capabilities: it still checks in and reports its
// controller's active key, and needs no KMS key.
func TestLoadAgent_NoCapabilities(t *testing.T) {
	for _, v := range []string{"", "none", " none "} {
		vars := agentEnv(map[string]string{"APP_CAPABILITIES": v})
		delete(vars, "APP_KMS_TRANSIT_KEY_ID")
		cfg, err := loadAgent(env(vars))
		if err != nil {
			t.Fatalf("%q: %v", v, err)
		}
		if len(cfg.Capabilities) != 0 {
			t.Errorf("%q: Capabilities = %v, want none", v, cfg.Capabilities)
		}
	}
	if _, err := loadAgent(env(agentEnv(map[string]string{"APP_CAPABILITIES": "none,seal"}))); err == nil || !strings.Contains(err.Error(), "none cannot be combined") {
		t.Fatalf("none with seal: %v", err)
	}
}

// A trailing slash in the control plane's URL must not reach the token
// audience: the control plane compares it with its own URL, without one.
func TestLoadAgent_TrailingSlash(t *testing.T) {
	cfg, err := loadAgent(env(agentEnv(map[string]string{"APP_CONTROL_PLANE_URL": "https://sealer.dev.example.com/"})))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ControlPlaneURL != "https://sealer.dev.example.com" || cfg.IdentityAudience != cfg.ControlPlaneURL {
		t.Errorf("url = %q, audience = %q", cfg.ControlPlaneURL, cfg.IdentityAudience)
	}
}

// A Deployment's name may contain dots, unlike a Service's.
func TestLoadAgent_ControllerDeploymentName(t *testing.T) {
	cfg, err := loadAgent(env(agentEnv(map[string]string{"APP_CONTROLLER_DEPLOYMENT": "sealed-secrets.controller"})))
	if err != nil || cfg.ControllerDeployment != "sealed-secrets.controller" {
		t.Fatalf("deployment = %q, err = %v", cfg.ControllerDeployment, err)
	}
	if _, err := loadAgent(env(agentEnv(map[string]string{"APP_CONTROLLER_DEPLOYMENT": "Not_Valid"}))); err == nil || !strings.Contains(err.Error(), "DNS-1123 subdomain") {
		t.Fatalf("invalid name: %v", err)
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

func TestLoadControlPlane_GitHub(t *testing.T) {
	cfg, err := loadControlPlane(env(controlPlaneEnv(nil)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GitHubURL != "https://github.com" || cfg.GitHubAPIURL != "https://api.github.com" ||
		cfg.GitHubOAuthTokenURL != "https://github.com/login/oauth/access_token" || cfg.UserSessionTTL != 8*time.Hour {
		t.Errorf("defaults = %+v", cfg)
	}

	local := controlPlaneEnv(map[string]string{
		"APP_GITHUB_URL":             "http://localhost:4104",
		"APP_GITHUB_API_URL":         "http://mock-github:8080",
		"APP_GITHUB_OAUTH_TOKEN_URL": "http://mock-github:8080/login/oauth/access_token",
		"APP_GITHUB_ALLOWED_TEAMS":   "sealers, admins",
	})
	if _, err := loadControlPlane(env(local)); err == nil || !strings.Contains(err.Error(), "APP_GITHUB_URL must be an absolute https URL") {
		t.Fatalf("http github accepted without the insecure flag: %v", err)
	}
	local["APP_ALLOW_INSECURE_GITHUB"] = "true"
	cfg, err = loadControlPlane(env(local))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.GitHubAllowedTeams) != 2 || cfg.GitHubAllowedTeams[1] != "admins" {
		t.Errorf("teams = %v", cfg.GitHubAllowedTeams)
	}

	missing := controlPlaneEnv(nil)
	delete(missing, "APP_GITHUB_OAUTH_CLIENT_SECRET")
	missing["APP_USER_SESSION_KEY"] = "short"
	_, err = loadControlPlane(env(missing))
	for _, want := range []string{"APP_GITHUB_OAUTH_CLIENT_SECRET is required", "APP_USER_SESSION_KEY must be at least 32 bytes"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
}
