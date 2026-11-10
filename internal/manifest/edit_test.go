package manifest

import (
	"errors"
	"strings"
	"testing"
)

func TestSetEncryptedData(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		edits []Edit
		want  string
	}{
		{
			name: "empty flow mapping in a block document becomes a block mapping",
			in: `# billing
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: billing
  namespace: apps
spec:
  encryptedData: {} # filled by the sealer
  template:
    metadata:
      labels:
        app: billing
`,
			edits: []Edit{{0, "api-token", "AgNew"}, {0, "db-password", "AgOther"}},
			want: `# billing
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: billing
  namespace: apps
spec:
  encryptedData: # filled by the sealer
    api-token: AgNew
    db-password: AgOther
  template:
    metadata:
      labels:
        app: billing
`,
		},
		{
			name: "null and tilde values",
			in: `kind: SealedSecret
spec:
    encryptedData:
---
kind: SealedSecret
spec:
  encryptedData: ~ # none yet
`,
			edits: []Edit{{0, "a", "AgA"}, {1, "b", "AgB"}},
			want: `kind: SealedSecret
spec:
    encryptedData:
        a: AgA
---
kind: SealedSecret
spec:
  encryptedData: # none yet
    b: AgB
`,
		},
		{
			name: "missing encryptedData goes first in spec, at its indentation",
			in: `kind: SealedSecret
spec:
    # the Secret to create
    template:
        type: Opaque
`,
			edits: []Edit{{0, "a", "AgA"}},
			want: `kind: SealedSecret
spec:
    encryptedData:
        a: AgA
    # the Secret to create
    template:
        type: Opaque
`,
		},
		{
			name: "sorted keys: replace in place, insert in order, keep comments and blank lines",
			in: `kind: SealedSecret
spec:
  encryptedData:
    # rotated in May
    b: AgOldB # keep this comment

    d: "AgOldD"
    f: AgOldF
    # end of data
  template: {}
`,
			edits: []Edit{{0, "a", "AgA"}, {0, "b", "AgB"}, {0, "c", "AgC"}, {0, "d", "AgD"}, {0, "z", "AgZ"}},
			want: `kind: SealedSecret
spec:
  encryptedData:
    a: AgA
    # rotated in May
    b: AgB # keep this comment
    c: AgC

    d: "AgD"
    f: AgOldF
    z: AgZ
    # end of data
  template: {}
`,
		},
		{
			name: "unsorted keys: new keys go last",
			in: `kind: SealedSecret
spec:
  encryptedData:
    z: AgZ
    a: AgA
`,
			edits: []Edit{{0, "m", "AgM"}},
			want: `kind: SealedSecret
spec:
  encryptedData:
    z: AgZ
    a: AgA
    m: AgM
`,
		},
		{
			name: "values over several lines are replaced whole",
			in: `kind: SealedSecret
spec:
  encryptedData:
    block: |
      AgOld1
      AgOld2

    folded: AgOld3
      AgOld4
    tagged: !!str AgOld5
    single: 'AgOld6'
  template: {}
`,
			edits: []Edit{{0, "block", "AgB"}, {0, "folded", "AgF"}, {0, "tagged", "AgT"}, {0, "single", "AgS"}},
			want: `kind: SealedSecret
spec:
  encryptedData:
    block: AgB

    folded: AgF
    tagged: AgT
    single: AgS
  template: {}
`,
		},
		{
			name: "value on the line after its key",
			in: `kind: SealedSecret
spec:
  encryptedData:
    a:
      AgOld
`,
			edits: []Edit{{0, "a", "AgNew"}},
			want: `kind: SealedSecret
spec:
  encryptedData:
    a:
      AgNew
`,
		},
		{
			name: "JSON document keeps JSON",
			in: `{
  "apiVersion": "bitnami.com/v1alpha1",
  "kind": "SealedSecret",
  "metadata": {"name": "s", "namespace": "apps"},
  "spec": {
    "encryptedData": {
      "b": "AgOldB"
    },
    "template": {"type": "Opaque"}
  }
}
`,
			edits: []Edit{{0, "a", "AgA"}, {0, "b", "AgB"}, {0, "c", "AgC"}},
			want: `{
  "apiVersion": "bitnami.com/v1alpha1",
  "kind": "SealedSecret",
  "metadata": {"name": "s", "namespace": "apps"},
  "spec": {
    "encryptedData": {
      "a": "AgA",
      "c": "AgC",
      "b": "AgB"
    },
    "template": {"type": "Opaque"}
  }
}
`,
		},
		{
			name: "JSON empty and null encryptedData",
			in: `{"kind": "SealedSecret", "spec": {"encryptedData": {}}}
---
{"kind": "SealedSecret", "spec": {"encryptedData": null, "template": {}}}
`,
			edits: []Edit{{0, "a", "AgA"}, {0, "b", "AgB"}, {1, "c", "AgC"}},
			want: `{"kind": "SealedSecret", "spec": {"encryptedData": {"a": "AgA", "b": "AgB"}}}
---
{"kind": "SealedSecret", "spec": {"encryptedData": {"c": "AgC"}, "template": {}}}
`,
		},
		{
			name: "YAML flow mapping on one line",
			in: `kind: SealedSecret
spec:
  encryptedData: {b: AgOldB, d: AgOldD}
`,
			edits: []Edit{{0, "a", "AgA"}, {0, "d", "AgD"}},
			want: `kind: SealedSecret
spec:
  encryptedData: {a: AgA, b: AgOldB, d: AgD}
`,
		},
		{
			name:  "CRLF line breaks and no final line break",
			in:    "kind: SealedSecret\r\nspec:\r\n  encryptedData:\r\n    b: AgOldB",
			edits: []Edit{{0, "b", "AgB"}, {0, "c", "AgC"}},
			want:  "kind: SealedSecret\r\nspec:\r\n  encryptedData:\r\n    b: AgB\r\n    c: AgC\r\n",
		},
		{
			name: "keys and values YAML 1.1 would misread are quoted",
			in: `kind: SealedSecret
spec:
  encryptedData: {}
`,
			edits: []Edit{{0, "on", "AgA"}, {0, "123", "AgB"}, {0, "true", "9999"}, {0, "_x", "+Ag/"}},
			want: `kind: SealedSecret
spec:
  encryptedData:
    "123": AgB
    _x: "+Ag/"
    "on": AgA
    "true": "9999"
`,
		},
		{
			name: "only the edited document changes; characters before a value are counted, not bytes",
			in: `kind: SealedSecret
metadata: {name: x} # résumé
spec:
  encryptedData:
    "é-not-a-key": AgOld # café
---
kind: SealedSecret
spec:
  encryptedData:
    a:   AgUntouched   # spacing kept
`,
			edits: []Edit{{0, "é-not-a-key", "AgNew"}},
			want:  "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SetEncryptedData([]byte(tt.in), tt.edits)
			if tt.want == "" {
				// the key is not a valid Secret key
				if err == nil {
					t.Fatalf("expected an error, got:\n%s", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("SetEncryptedData: %v", err)
			}
			if string(got) != tt.want {
				t.Fatalf("got:\n%s\nwant:\n%s", got, tt.want)
			}
		})
	}
}

func TestSetEncryptedData_KeepsOtherDocumentsAndMultibyteText(t *testing.T) {
	in := `kind: SealedSecret
metadata: {name: x} # résumé
spec:
  encryptedData:
    "ключ": AgOld # café
    b: AgOldB
---
kind: SealedSecret
spec:
  encryptedData:
    a:   AgUntouched   # spacing kept
`
	got, err := SetEncryptedData([]byte(in), []Edit{{0, "b", "AgB"}, {0, "c", "AgC"}})
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(in, "    b: AgOldB\n", "    b: AgB\n    c: AgC\n", 1)
	if string(got) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}

	in = "kind: SealedSecret\nspec:\n  encryptedData:\n    \"ключ\": AgOld # café\n"
	got, err = SetEncryptedData([]byte(in), []Edit{{0, "x", "AgX"}})
	if err != nil {
		t.Fatal(err)
	}
	// the multibyte key sorts after "x"
	if want := "kind: SealedSecret\nspec:\n  encryptedData:\n    x: AgX\n    \"ключ\": AgOld # café\n"; string(got) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestSetEncryptedData_Refuses(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		edits []Edit
	}{
		{"anchored spec", "base: &b {encryptedData: {}}\nspec: *b\n", nil},
		{"anchored encryptedData", "spec:\n  encryptedData: &d\n    a: AgA\n", nil},
		{"aliased value", "v: &v AgA\nspec:\n  encryptedData:\n    a: *v\n", []Edit{{0, "a", "AgB"}}},
		{"anchored value", "spec:\n  encryptedData:\n    a: &v AgA\n", []Edit{{0, "a", "AgB"}}},
		{"merge key", "d: &d {x: AgX}\nspec:\n  encryptedData:\n    <<: *d\n    a: AgA\n", nil},
		{"sequence", "spec:\n  encryptedData: [AgA]\n", nil},
		{"string", "spec:\n  encryptedData: AgA\n", nil},
		{"nested value", "spec:\n  encryptedData:\n    a:\n      b: AgA\n", []Edit{{0, "a", "AgB"}}},
		{"no spec", "kind: SealedSecret\n", nil},
		{"flow spec without encryptedData", "spec: {template: {}}\n", nil},
		{"not a mapping", "- a\n", nil},
		{"invalid key", "spec:\n  encryptedData: {}\n", []Edit{{0, "a/b", "AgA"}}},
		{"value not base64", "spec:\n  encryptedData: {}\n", []Edit{{0, "a", "Ag A"}}},
		{"value with a line break", "spec:\n  encryptedData: {}\n", []Edit{{0, "a", "Ag\nA"}}},
		{"no such document", "spec:\n  encryptedData: {}\n", []Edit{{1, "a", "AgA"}}},
		{"key set twice", "spec:\n  encryptedData: {}\n", []Edit{{0, "a", "AgA"}, {0, "a", "AgB"}}},
		{"duplicate key in the file", "spec:\n  encryptedData:\n    a: AgA\n    a: AgB\n", nil},
		{"invalid YAML", "spec: [\n", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			edits := tt.edits
			if edits == nil {
				edits = []Edit{{0, "new", "AgNew"}}
			}
			got, err := SetEncryptedData([]byte(tt.in), edits)
			if err == nil {
				t.Fatalf("expected an error, got:\n%s", got)
			}
		})
	}
}

func TestVerify_RefusesChangesOutsideEncryptedData(t *testing.T) {
	before := []byte("metadata: {name: a}\nspec:\n  encryptedData: {}\n")
	after := []byte("metadata: {name: b}\nspec:\n  encryptedData: {k: AgK}\n")
	if err := verify(before, after, []Edit{{0, "k", "AgK"}}); !errors.Is(err, ErrLayout) {
		t.Fatalf("verify = %v, want ErrLayout", err)
	}
	after = []byte("metadata: {name: a}\nspec:\n  encryptedData: {k: AgK}\n")
	if err := verify(before, after, []Edit{{0, "k", "AgK"}}); err != nil {
		t.Fatalf("verify = %v", err)
	}
}

func TestSetEncryptedData_Fixture(t *testing.T) {
	in := `# two envs
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: billing
  namespace: dev-apps
  annotations:
    k8s-sealed-secrets-sealer/env: dev
spec:
  encryptedData: {}
---
# another env's document
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: billing
  namespace: billing
  annotations:
    k8s-sealed-secrets-sealer/env: prod
spec:
  encryptedData:
    api-key: AgBplaceholder==
`
	docs, err := Find([]byte(in), Annotations{Env: DefaultEnvAnnotation}, "dev")
	if err != nil || len(docs) != 1 {
		t.Fatalf("Find = %v, %v", docs, err)
	}
	got, err := SetEncryptedData([]byte(in), []Edit{{docs[0].Index, "api-key", "AgDev=="}})
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(in, "spec:\n  encryptedData: {}\n", "spec:\n  encryptedData:\n    api-key: AgDev==\n", 1)
	if string(got) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	after, err := Find(got, Annotations{Env: DefaultEnvAnnotation}, "dev")
	if err != nil || len(after) != 1 || strings.Join(after[0].Keys, ",") != "api-key" || after[0].Problem != "" {
		t.Fatalf("Find after the edit = %+v, %v", after, err)
	}
}

// FuzzSetEncryptedData checks that the editor never panics and that whatever
// it returns passed its own check.
func FuzzSetEncryptedData(f *testing.F) {
	for _, seed := range []string{
		"spec:\n  encryptedData: {}\n",
		"spec:\n  encryptedData:\n    a: AgA # c\n    b: |\n      x\n",
		"{\"spec\": {\"encryptedData\": {\"a\": \"AgA\"}}}",
		"spec:\n  encryptedData: ~\r\n  template: {}",
		"a: 1\n---\nspec:\n    template: {}\n",
	} {
		f.Add(seed, "a")
		f.Add(seed, "z")
	}
	f.Fuzz(func(t *testing.T, in, key string) {
		docs, err := parse([]byte(in))
		if err != nil || len(docs) == 0 {
			return
		}
		got, err := SetEncryptedData([]byte(in), []Edit{{0, key, "AgNew"}})
		if err != nil {
			return
		}
		if err := verify([]byte(in), got, []Edit{{0, key, "AgNew"}}); err != nil {
			t.Fatalf("result fails verification: %v", err)
		}
	})
}
