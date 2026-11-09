package registry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const valid = `
issuers:
  - name: local
    url: https://kubernetes.default.svc.cluster.local
    jwksFile: jwks/local.json
  - name: remote
    url: https://oidc.example.com/id/ABC
    jwksURL: https://oidc.example.com/id/ABC/keys
agents:
  - id: use2-blue
    cluster: blue
    region: use2
    capabilities: [seal]
    identity:
      k8s: {issuer: remote, subject: "system:serviceaccount:sealer:sealer-agent"}
  - id: use1-blue
    cluster: blue
    region: use1
    capabilities: [seal, keys, renewal]
    identity:
      k8s: {issuer: local, subject: "system:serviceaccount:sealer:sealer-agent"}
`

func TestParse_Valid(t *testing.T) {
	r, err := Parse([]byte(valid), "/etc/registry")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(r.Agents) != 2 || r.Agents[0].ID != "use1-blue" {
		t.Fatalf("agents not sorted by id: %+v", r.Agents)
	}
	a, ok := r.AgentByK8s("local", "system:serviceaccount:sealer:sealer-agent")
	if !ok || a.ID != "use1-blue" {
		t.Fatalf("AgentByK8s = %v, %v", a, ok)
	}
	if _, ok := r.AgentByK8s("local", "system:serviceaccount:other:sealer-agent"); ok {
		t.Fatal("unregistered subject was found")
	}
	if !a.HasCapability("keys") {
		t.Error("capabilities not kept")
	}
	if got := r.Issuers[0].JWKSFile; got != "/etc/registry/jwks/local.json" {
		t.Errorf("relative jwksFile resolved to %q", got)
	}
}

func TestParse_ReportsEveryProblem(t *testing.T) {
	bad := `
issuers:
  - name: local
    url: http://insecure.example.com
    jwksFile: a.json
    jwksURL: https://x.example.com/keys
  - name: local
    url: https://ok.example.com
agents:
  - id: Bad_ID
    cluster: blue
    region: use1
    capabilities: [seal, seal, root]
    identity: {}
  - id: dup
    cluster: blue
    region: use1
    identity:
      k8s: {issuer: missing, subject: "user:alice"}
  - id: dup
    cluster: ""
    region: use1
    identity:
      k8s: {issuer: local, subject: "system:serviceaccount:ns:sa"}
`
	_, err := Parse([]byte(bad), "")
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{
		"url must be an absolute https URL",
		"set exactly one of jwksURL and jwksFile",
		`duplicate issuer "local"`,
		"id must be a DNS-1123 label",
		`duplicate capability "seal"`,
		`unknown capability "root"`,
		"identity.k8s is required",
		`unknown issuer "missing"`,
		"subject must be system:serviceaccount",
		"duplicate id",
		"cluster must be a DNS-1123 label",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q:\n%v", want, err)
		}
	}
}

func TestParse_RejectsDuplicateIdentityAndUnknownFields(t *testing.T) {
	dupIdentity := `
issuers: [{name: local, url: "https://i.example.com", jwksFile: k.json}]
agents:
  - {id: a, cluster: a, region: r, identity: {k8s: {issuer: local, subject: "system:serviceaccount:ns:sa"}}}
  - {id: b, cluster: b, region: r, identity: {k8s: {issuer: local, subject: "system:serviceaccount:ns:sa"}}}
`
	if _, err := Parse([]byte(dupIdentity), ""); err == nil || !strings.Contains(err.Error(), `already registered for agent "a"`) {
		t.Errorf("duplicate identity: %v", err)
	}
	if _, err := Parse([]byte("agents: []\nextra: true\n"), ""); err == nil || !strings.Contains(err.Error(), "failed to parse") {
		t.Errorf("unknown field: %v", err)
	}
	if _, err := Parse([]byte("issuers: []\nagents: []\n"), ""); err == nil || !strings.Contains(err.Error(), "at least one agent") {
		t.Errorf("empty registry: %v", err)
	}
}

func TestLoad_ResolvesAgainstFileDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "registry.yaml")
	if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Issuers[0].JWKSFile; got != filepath.Join(dir, "jwks/local.json") {
		t.Errorf("jwksFile = %q", got)
	}
}
