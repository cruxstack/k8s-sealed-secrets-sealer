package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/agentauth"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/config"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/testutil/testcerts"
)

const issuers = `issuers: [{name: blue, url: "https://oidc.example.com/blue", jwksURL: "https://oidc.example.com/blue/keys"}]
`

func agentLine(id, identity string) string {
	return "  - {id: " + id + ", cluster: " + id + ", region: use1, identity: " + identity + "}\n"
}

func role(name string) string {
	return `{aws: {roleArn: "arn:aws:iam::111111111111:role/` + name + `"}}`
}

func serviceAccount(name string) string {
	return `{k8s: {issuer: blue, subject: "system:serviceaccount:sealer:` + name + `"}}`
}

func newTestEnvRegistry(env string, cfg *config.ControlPlane, all *envRegistries) *envRegistry {
	cfg.EnvName = env
	return &envRegistry{
		env: env,
		cfg: cfg,
		logins: &envLogins{
			audience: "https://sealer.example.com",
			replays:  store.NewMemory(),
			stsLimit: agentauth.NewSTSLimiter(),
		},
		all: all,
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestEnvRegistry_ReloadsAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.yaml")
	writeFile(t, path, issuers+"agents:\n"+agentLine("blue", serviceAccount("blue"))+agentLine("green", role("green")))
	r := newTestEnvRegistry("dev", &config.ControlPlane{RegistryFile: path}, newEnvRegistries())
	ctx := context.Background()

	reg, logins, err := r.start(ctx)
	if err != nil || len(reg.Agents) != 2 || logins[protocol.MethodK8sOIDC] == nil || logins[protocol.MethodAWSSTS] == nil {
		t.Fatalf("start = %v, %v, %v", reg, logins, err)
	}
	if !r.reloadable() {
		t.Fatal("a registry file is not read again")
	}
	if reg, _, err := r.reload(ctx); reg != nil || err != nil {
		t.Fatalf("unchanged registry = %v, %v; want nil, nil", reg, err)
	}

	// an agent is removed
	writeFile(t, path, issuers+"agents:\n"+agentLine("green", role("green")))
	reg, logins, err = r.reload(ctx)
	if err != nil || len(reg.Agents) != 1 || reg.Agents[0].ID != "green" || len(logins) != 2 {
		t.Fatalf("changed registry = %v, %v, %v", reg, logins, err)
	}
	// a broken registry is refused, and the one in force stays
	writeFile(t, path, "agents: [{id: Not_A_Label}]\n")
	if reg, _, err := r.reload(ctx); reg != nil || err == nil || !strings.Contains(err.Error(), "invalid agent registry "+path) {
		t.Fatalf("broken registry = %v, %v", reg, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if reg, _, err := r.reload(ctx); reg != nil || err == nil || !strings.Contains(err.Error(), "failed to read agent registry") {
		t.Fatalf("missing registry = %v, %v", reg, err)
	}
}

// The registry's JWKS and CA files live beside it (the chart's ConfigMap)
// and change without it: a change to one is a change of the registry.
func TestEnvRegistry_ReloadsTheFilesItReferences(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "registry.yaml")
	jwks := filepath.Join(dir, "green-jwks.json")
	ca := filepath.Join(dir, "blue-ca.pem")
	writeFile(t, jwks, `{"keys": [{"kty": "EC", "crv": "P-256", "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0", "use": "sig", "kid": "one"}]}`)
	writeFile(t, ca, string(testcerts.SelfSigned(t, testcerts.ECDSA(t), time.Now())))
	writeFile(t, path, `issuers:
  - {name: blue, url: "https://oidc.example.com/blue", jwksURL: "https://oidc.example.com/blue/keys", caFile: blue-ca.pem}
  - {name: green, url: "https://oidc.example.com/green", jwksFile: green-jwks.json}
agents:
`+agentLine("green", `{k8s: {issuer: green, subject: "system:serviceaccount:sealer:green"}}`))
	r := newTestEnvRegistry("dev", &config.ControlPlane{RegistryFile: path}, newEnvRegistries())
	ctx := context.Background()
	if _, _, err := r.start(ctx); err != nil {
		t.Fatal(err)
	}
	if reg, _, err := r.reload(ctx); reg != nil || err != nil {
		t.Fatalf("nothing changed = %v, %v; want nil, nil", reg, err)
	}

	// the issuer's keys rotate
	writeFile(t, jwks, `{"keys": [{"kty": "EC", "crv": "P-256", "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0", "use": "sig", "kid": "two"}]}`)
	if reg, logins, err := r.reload(ctx); reg == nil || logins == nil || err != nil {
		t.Fatalf("a JWKS file changed = %v, %v; want the registry again", reg, err)
	}
	if reg, _, err := r.reload(ctx); reg != nil || err != nil {
		t.Fatalf("nothing changed since = %v, %v; want nil, nil", reg, err)
	}

	// a CA bundle changes
	writeFile(t, ca, string(testcerts.SelfSigned(t, testcerts.ECDSA(t), time.Now())))
	if reg, _, err := r.reload(ctx); reg == nil || err != nil {
		t.Fatalf("a CA file changed = %v, %v; want the registry again", reg, err)
	}

	// a file that cannot be read leaves the registry in force
	if err := os.Remove(jwks); err != nil {
		t.Fatal(err)
	}
	if reg, _, err := r.reload(ctx); reg != nil || err == nil || !strings.Contains(err.Error(), "issuer green") {
		t.Fatalf("a JWKS file missing = %v, %v", reg, err)
	}
}

func TestEnvRegistry_ReloadsAParameter(t *testing.T) {
	const arn = "arn:aws:ssm:us-east-2:111111111111:parameter/sealer/dev/registry"
	value := "agents:\n" + agentLine("green", role("green"))
	// the configuration read the parameter at start, and trimmed it
	r := newTestEnvRegistry("dev", &config.ControlPlane{Registry: []byte(strings.TrimSpace(value)), RegistryParameter: arn}, newEnvRegistries())
	r.read = func(_ context.Context, got string) (string, error) {
		if got != arn {
			t.Errorf("read %s, want %s", got, arn)
		}
		return value, nil
	}
	ctx := context.Background()
	if _, _, err := r.start(ctx); err != nil {
		t.Fatal(err)
	}
	if !r.reloadable() {
		t.Fatal("a registry parameter is not read again")
	}
	if reg, _, err := r.reload(ctx); reg != nil || err != nil {
		t.Fatalf("unchanged parameter = %v, %v; want nil, nil", reg, err)
	}
	value += agentLine("blue", role("blue"))
	if reg, _, err := r.reload(ctx); err != nil || reg == nil || len(reg.Agents) != 2 {
		t.Fatalf("changed parameter = %v, %v", reg, err)
	}
}

func TestEnvRegistry_InlineIsNotReloaded(t *testing.T) {
	r := newTestEnvRegistry("dev", &config.ControlPlane{Registry: []byte("agents:\n" + agentLine("green", role("green")))}, newEnvRegistries())
	if _, _, err := r.start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.reloadable() {
		t.Fatal("an inline registry is read again")
	}
}

// Envs on one URL share the agent audience, so an identity registered in
// two of them could use one login in both.
func TestEnvRegistry_RefusesAnIdentityInTwoEnvs(t *testing.T) {
	ctx := context.Background()
	all := newEnvRegistries()
	dev := newTestEnvRegistry("dev", &config.ControlPlane{
		Registry: []byte(issuers + "agents:\n" + agentLine("dev-blue", serviceAccount("blue")) + agentLine("dev-green", role("green"))),
	}, all)
	if _, _, err := dev.start(ctx); err != nil {
		t.Fatal(err)
	}

	// at start
	prod := newTestEnvRegistry("prod", &config.ControlPlane{
		Registry: []byte(issuers + "agents:\n" + agentLine("prod-blue", serviceAccount("blue")) + agentLine("prod-green", role("sealer/green"))),
	}, all)
	_, _, err := prod.start(ctx)
	for _, want := range []string{
		"an agent identity is registered in another env",
		`agent "prod-blue": service account system:serviceaccount:sealer:blue of issuer https://oidc.example.com/blue is also agent "dev-blue"'s in env dev`,
		`agent "prod-green": IAM role green in account 111111111111 (aws) is also agent "dev-green"'s in env dev`,
	} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("prod with dev's identities = %v; want it to say %q", err, want)
		}
	}

	// on a reload
	path := filepath.Join(t.TempDir(), "prod.yaml")
	writeFile(t, path, issuers+"agents:\n"+agentLine("prod-blue", serviceAccount("prod-blue")))
	prod = newTestEnvRegistry("prod", &config.ControlPlane{RegistryFile: path}, all)
	if _, _, err := prod.start(ctx); err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, issuers+"agents:\n"+agentLine("prod-blue", serviceAccount("prod-blue"))+agentLine("prod-green", role("green")))
	if reg, _, err := prod.reload(ctx); reg != nil || err == nil || !strings.Contains(err.Error(), `is also agent "dev-green"'s in env dev`) {
		t.Fatalf("reload taking dev's identity = %v, %v", reg, err)
	}
	if got := len(all.regs["prod"].Agents); got != 1 {
		t.Fatalf("prod's registry in force has %d agents, want 1", got)
	}

	// once dev lets the identity go, prod may take it
	devPath := filepath.Join(t.TempDir(), "dev.yaml")
	writeFile(t, devPath, issuers+"agents:\n"+agentLine("dev-blue", serviceAccount("blue")))
	dev.cfg = &config.ControlPlane{EnvName: "dev", RegistryFile: devPath}
	if reg, _, err := dev.reload(ctx); err != nil || len(reg.Agents) != 1 {
		t.Fatalf("dev reload = %v, %v", reg, err)
	}
	if reg, _, err := prod.reload(ctx); err != nil || len(reg.Agents) != 2 {
		t.Fatalf("prod reload = %v, %v", reg, err)
	}
}
