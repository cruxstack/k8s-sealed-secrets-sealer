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
    capabilities: [seal, keys, renewal, cleanup]
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
	if !a.HasCapability("keys") || !a.HasCapability("cleanup") {
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
  - name: again
    url: https://ok.example.com
    jwksURL: https://ok.example.com/keys
agents:
  - id: Bad_ID
    cluster: blue
    region: USE1
    capabilities: [seal, seal, root]
    identity: {}
  - id: dup
    cluster: blue
    region: use1
    capabilities: [seal, cleanup, reseal]
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
		`capability "cleanup" needs "keys"`,
		`capability "reseal" needs "keys"`,
		"set exactly one of identity.k8s and identity.aws",
		`unknown issuer "missing"`,
		"subject must be system:serviceaccount",
		"duplicate id",
		"cluster must be a DNS-1123 label",
		"region must be a DNS-1123 label",
		`issuers[2]: url is also issuer "local"'s`,
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

func TestParse_AWSIdentities(t *testing.T) {
	r, err := Parse([]byte(`
agents:
  - id: use1-blue
    cluster: blue
    region: use1
    capabilities: [seal]
    identity:
      aws: {roleArn: "arn:aws:iam::123456789012:role/sealer/use1-blue", roleId: AROA1234567890ABCDEFG}
  - id: gov-blue
    cluster: blue
    region: usgw1
    identity:
      aws: {roleArn: "arn:aws-us-gov:iam::210987654321:role/use1-blue"}
`), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// STS reports assumed roles without their path
	a, ok := r.AgentByAWSRole(AWSRole{Partition: "aws", Account: "123456789012", Name: "use1-blue"})
	if !ok || a.ID != "use1-blue" || a.Identity.AWS.RoleID != "AROA1234567890ABCDEFG" {
		t.Fatalf("AgentByAWSRole = %v, %v", a, ok)
	}
	if _, ok := r.AgentByAWSRole(AWSRole{Partition: "aws", Account: "999999999999", Name: "use1-blue"}); ok {
		t.Fatal("a role in another account was found")
	}
	if a, ok := r.AgentByAWSRole(AWSRole{Partition: "aws-us-gov", Account: "210987654321", Name: "use1-blue"}); !ok || a.ID != "gov-blue" {
		t.Fatalf("gov partition: %v, %v", a, ok)
	}
}

func TestParse_RejectsBadAWSIdentities(t *testing.T) {
	bad := `
issuers: [{name: local, url: "https://i.example.com", jwksFile: k.json}]
agents:
  - {id: a, cluster: a, region: r, identity: {aws: {roleArn: "arn:aws:iam::123:role/short-account"}}}
  - {id: b, cluster: b, region: r, identity: {aws: {roleArn: "arn:aws:iam::123456789012:user/alice"}}}
  - {id: c, cluster: c, region: r, identity: {aws: {roleArn: "arn:aws:iam::123456789012:role/x", roleId: "AIDAUSERID"}}}
  - {id: d, cluster: d, region: r, identity: {aws: {roleArn: "arn:aws:iam::123456789012:role/p1/same"}}}
  - {id: e, cluster: e, region: r, identity: {aws: {roleArn: "arn:aws:iam::123456789012:role/p2/same"}}}
  - id: f
    cluster: f
    region: r
    identity:
      aws: {roleArn: "arn:aws:iam::123456789012:role/f"}
      k8s: {issuer: local, subject: "system:serviceaccount:ns:sa"}
`
	_, err := Parse([]byte(bad), "")
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{
		`agent "a": roleArn must be an IAM role ARN`,
		`agent "b": roleArn must be an IAM role ARN`,
		`agent "c": roleId must be`,
		`agent "e": role already registered for agent "d"`,
		`agent "f": set exactly one of identity.k8s and identity.aws`,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q:\n%v", want, err)
		}
	}
}

func TestSharedIdentities(t *testing.T) {
	dev, err := Parse([]byte(`
issuers: [{name: blue, url: "https://oidc.example.com/blue", jwksFile: k.json}]
agents:
  - {id: dev-blue, cluster: blue, region: use1, identity: {k8s: {issuer: blue, subject: "system:serviceaccount:sealer:agent"}}}
  - {id: dev-green, cluster: green, region: use1, identity: {aws: {roleArn: "arn:aws:iam::111111111111:role/sealer/green"}}}
  - {id: dev-red, cluster: red, region: use1, identity: {aws: {roleArn: "arn:aws:iam::111111111111:role/red"}}}
`), "")
	if err != nil {
		t.Fatal(err)
	}
	// the same issuer under another name, the same role under another path
	prod, err := Parse([]byte(`
issuers: [{name: shared, url: "https://oidc.example.com/blue", jwksURL: "https://oidc.example.com/blue/keys"}]
agents:
  - {id: prod-blue, cluster: blue, region: use1, identity: {k8s: {issuer: shared, subject: "system:serviceaccount:sealer:agent"}}}
  - {id: prod-green, cluster: green, region: use1, identity: {aws: {roleArn: "arn:aws:iam::111111111111:role/other-path/green"}}}
  - {id: prod-red, cluster: red, region: use1, identity: {aws: {roleArn: "arn:aws:iam::222222222222:role/red"}}}
  - {id: prod-sa, cluster: sa, region: use1, identity: {k8s: {issuer: shared, subject: "system:serviceaccount:sealer:other"}}}
`), "")
	if err != nil {
		t.Fatal(err)
	}
	got := SharedIdentities(prod, dev)
	want := []string{
		`agent "prod-blue": service account system:serviceaccount:sealer:agent of issuer https://oidc.example.com/blue is also agent "dev-blue"'s`,
		`agent "prod-green": IAM role green in account 111111111111 (aws) is also agent "dev-green"'s`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("SharedIdentities =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if got := SharedIdentities(dev, dev); len(got) != 3 {
		t.Errorf("a registry shares %d identities with itself, want 3", len(got))
	}
}

// A session carries its agent's binding, so a registry change that rebinds
// an ID must change it, and one that leaves the agent alone must not.
func TestBinding(t *testing.T) {
	binding := func(agents string) string {
		t.Helper()
		r, err := Parse([]byte(`
issuers:
  - {name: blue, url: "https://oidc.example.com/blue", jwksFile: k.json}
  - {name: green, url: "https://oidc.example.com/green", jwksFile: k.json}
agents:
  - {id: other, cluster: other, region: use1, identity: {aws: {roleArn: "arn:aws:iam::111111111111:role/other"}}}
`+agents), "")
		if err != nil {
			t.Fatal(err)
		}
		a, _ := r.Agent("use1-blue")
		return r.Binding(a)
	}
	const agent = `  - {id: use1-blue, cluster: blue, region: use1, capabilities: [seal, keys], identity: {k8s: {issuer: blue, subject: "system:serviceaccount:sealer:agent"}}}`
	base := binding(agent)
	same := map[string]string{
		"capabilities reordered": strings.Replace(agent, "[seal, keys]", "[keys, seal]", 1),
		"another region":         strings.Replace(agent, "region: use1", "region: use2", 1),
	}
	for name, a := range same {
		if got := binding(a); got != base {
			t.Errorf("%s: binding changed", name)
		}
	}
	changed := map[string]string{
		"another subject":       strings.Replace(agent, "sealer:agent", "sealer:other", 1),
		"another issuer":        strings.Replace(agent, "issuer: blue", "issuer: green", 1),
		"another capability":    strings.Replace(agent, "[seal, keys]", "[seal, keys, renewal]", 1),
		"a capability less":     strings.Replace(agent, "[seal, keys]", "[seal]", 1),
		"an IAM role instead":   `  - {id: use1-blue, cluster: blue, region: use1, capabilities: [seal, keys], identity: {aws: {roleArn: "arn:aws:iam::111111111111:role/blue"}}}`,
		"the role's ID pinned":  `  - {id: use1-blue, cluster: blue, region: use1, capabilities: [seal, keys], identity: {aws: {roleArn: "arn:aws:iam::111111111111:role/blue", roleId: AROA1234567890ABCDEFG}}}`,
		"a role in another acc": `  - {id: use1-blue, cluster: blue, region: use1, capabilities: [seal, keys], identity: {aws: {roleArn: "arn:aws:iam::222222222222:role/blue"}}}`,
	}
	seen := map[string]string{base: "the agent"}
	for name, a := range changed {
		got := binding(a)
		if other, dup := seen[got]; dup {
			t.Errorf("%s: binding is the same as for %s", name, other)
		}
		seen[got] = name
	}
}
