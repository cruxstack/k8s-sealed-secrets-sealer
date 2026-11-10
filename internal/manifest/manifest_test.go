package manifest

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/mockgithub"
)

var ann = Annotations{Env: DefaultEnvAnnotation, Region: DefaultRegionAnnotation}

func TestFind_MultiDocumentFile(t *testing.T) {
	repos, err := mockgithub.Fixtures()
	if err != nil {
		t.Fatal(err)
	}
	content := repos[0].Files["deploy/billing/sealed-secret.yaml"]
	docs, err := Find([]byte(content), ann, "dev")
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 3 {
		t.Fatalf("found %d dev documents, want 3: %+v", len(docs), docs)
	}
	want := []Document{
		{Index: 0, Name: "billing", Namespace: "dev-use1-blue-apps", Region: "use1", Scope: ScopeStrict, Keys: []string{}},
		{Index: 1, Name: "billing", Namespace: "dev-use1-green-apps", Region: "use1", Scope: ScopeStrict, Keys: []string{}},
		{Index: 2, Name: "billing", Namespace: "dev-use2-blue-apps", Region: "use2", Scope: ScopeStrict, Keys: []string{}},
	}
	for i, d := range docs {
		w := want[i]
		if d.Index != w.Index || d.Name != w.Name || d.Namespace != w.Namespace || d.Region != w.Region || d.Scope != w.Scope || len(d.Keys) != 0 || !d.Sealable() {
			t.Errorf("document %d = %+v, want %+v", i, d, w)
		}
	}

	prod, err := Find([]byte(content), ann, "prod")
	if err != nil || len(prod) != 1 || prod[0].Index != 3 || !slices.Equal(prod[0].Keys, []string{"api-key"}) {
		t.Fatalf("prod documents = %+v, %v", prod, err)
	}
}

func TestFind_ScopesAndProblems(t *testing.T) {
	const tmpl = `
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: NAME
  namespace: NS
  annotations:
    k8s-sealed-secrets-sealer/env: dev
EXTRA
spec:
  SPEC
`
	doc := func(name, ns, extra, spec string) string {
		r := strings.NewReplacer("NAME", name, "NS", ns, "EXTRA", extra, "SPEC", spec)
		return r.Replace(tmpl)
	}
	cases := map[string]struct {
		yaml    string
		scope   string
		problem string
	}{
		"strict":         {doc("a", "ns", "", "encryptedData: {b: x, a: y}"), ScopeStrict, ""},
		"namespace-wide": {doc("a", "ns", `    sealedsecrets.bitnami.com/namespace-wide: "true"`, "encryptedData: {}"), ScopeNamespaceWide, ""},
		"cluster-wide":   {doc("a", "ns", `    sealedsecrets.bitnami.com/cluster-wide: "true"`, "encryptedData: {}"), ScopeClusterWide, "cluster-wide"},
		"no namespace":   {doc("a", "", "", "encryptedData: {}"), ScopeStrict, "namespace is missing"},
		"bad namespace":  {doc("a", "Not_OK", "", "encryptedData: {}"), ScopeStrict, "not a valid namespace"},
		"no name":        {doc("", "ns", "", "encryptedData: {}"), ScopeStrict, "name is missing"},
		"legacy data":    {doc("a", "ns", "", "data: AgB="), ScopeStrict, "legacy spec.data"},
		"list data":      {doc("a", "ns", "", "encryptedData: [x]"), ScopeStrict, "not a mapping"},
		"null data":      {doc("a", "ns", "", "encryptedData:"), ScopeStrict, ""},
		"other version":  {strings.Replace(doc("a", "ns", "", "encryptedData: {}"), "v1alpha1", "v2", 1), ScopeStrict, "apiVersion"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			docs, err := Find([]byte(tc.yaml), ann, "dev")
			if err != nil || len(docs) != 1 {
				t.Fatalf("docs = %+v, err = %v", docs, err)
			}
			d := docs[0]
			if d.Scope != tc.scope || (tc.problem == "") != d.Sealable() || !strings.Contains(d.Problem, tc.problem) {
				t.Fatalf("document = %+v, want scope %s and problem %q", d, tc.scope, tc.problem)
			}
		})
	}
	docs, _ := Find([]byte(cases["strict"].yaml), ann, "dev")
	if !slices.Equal(docs[0].Keys, []string{"a", "b"}) {
		t.Errorf("keys = %v, want sorted [a b]", docs[0].Keys)
	}
}

func TestFind_IgnoresOtherDocuments(t *testing.T) {
	content := `
apiVersion: v1
kind: ConfigMap
metadata:
  name: x
  annotations:
    k8s-sealed-secrets-sealer/env: dev
---
- a list
---
plain scalar
---
---
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: no-env
  namespace: ns
`
	docs, err := Find([]byte(content), ann, "dev")
	if err != nil || len(docs) != 0 {
		t.Fatalf("docs = %+v, err = %v", docs, err)
	}
	// custom annotation keys
	custom := strings.Replace(content, "name: no-env\n  namespace: ns", "name: s\n  namespace: ns\n  annotations: {acme.io/env: dev, acme.io/region: eu}", 1)
	docs, err = Find([]byte(custom), Annotations{Env: "acme.io/env", Region: "acme.io/region"}, "dev")
	// the empty document is not counted
	if err != nil || len(docs) != 1 || docs[0].Index != 4 || docs[0].Region != "eu" {
		t.Fatalf("custom annotations: docs = %+v, err = %v", docs, err)
	}
}

func TestFind_Rejects(t *testing.T) {
	if _, err := Find([]byte("a: [unclosed"), ann, "dev"); !errors.Is(err, ErrInvalidYAML) {
		t.Errorf("invalid yaml: %v", err)
	}
	dup := "kind: SealedSecret\nmetadata:\n  name: a\n  namespace: one\n  namespace: two\n"
	if _, err := Find([]byte(dup), ann, "dev"); !errors.Is(err, ErrDuplicateKey) {
		t.Errorf("duplicate keys: %v", err)
	}
	if _, err := Find([]byte(strings.Repeat("---\na: 1\n", MaxDocuments+1)), ann, "dev"); !errors.Is(err, ErrTooMany) {
		t.Errorf("too many documents: %v", err)
	}
	if _, err := Find(make([]byte, MaxFileBytes+1), ann, "dev"); !errors.Is(err, ErrTooLarge) {
		t.Errorf("too large: %v", err)
	}
	// an alias bomb is bounded by the parser
	bomb := "a: &a [x, x, x, x, x, x, x, x, x]\nb: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]\nc: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b]\nd: &d [*c, *c, *c, *c, *c, *c, *c, *c, *c]\n"
	if _, err := Find([]byte(bomb), ann, "dev"); err != nil {
		t.Errorf("small alias use refused: %v", err)
	}
}

func TestFind_Hints(t *testing.T) {
	in := `apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: billing
  namespace: apps
  annotations:
    example.com/env: dev
    example.com/description: |
      Billing service credentials,
      rotated ` + "\u202e" + `quarterly.` + "\u200b" + `
    example.com/keys: "api-token, db-password api-token bad/key"
    example.com/docs: https://docs.example.com/runbooks/billing
spec:
  encryptedData: {}
---
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: other
  namespace: apps
  annotations:
    example.com/env: dev
    example.com/docs: "javascript:alert(1)"
    example.com/description: "` + strings.Repeat("x", 400) + `"
spec:
  encryptedData: {}
`
	ann := Annotations{Env: "example.com/env"}
	if ann.Hint("keys") != "example.com/keys" || (Annotations{Env: "env"}).Hint("docs") != DefaultPrefix+"/docs" {
		t.Fatalf("hint keys: %s, %s", ann.Hint("keys"), (Annotations{Env: "env"}).Hint("docs"))
	}
	docs, err := Find([]byte(in), ann, "dev")
	if err != nil || len(docs) != 2 {
		t.Fatalf("Find = %+v, %v", docs, err)
	}
	d := docs[0]
	if d.Description != "Billing service credentials, rotated quarterly." ||
		strings.Join(d.ExpectedKeys, ",") != "api-token,db-password" ||
		d.Docs != "https://docs.example.com/runbooks/billing" || d.Problem != "" {
		t.Fatalf("hints = %q %q %q", d.Description, d.ExpectedKeys, d.Docs)
	}
	// an unsafe link is dropped and a long description cut
	if docs[1].Docs != "" || len([]rune(docs[1].Description)) != maxDescriptionRunes || !strings.HasSuffix(docs[1].Description, "…") {
		t.Fatalf("other hints = %q (%d), %q", docs[1].Description, len(docs[1].Description), docs[1].Docs)
	}
}
