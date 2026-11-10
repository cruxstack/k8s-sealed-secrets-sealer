package repos

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/manifest"
)

var billingTargets = []Target{
	{Namespace: "dev-use1-blue-apps", Name: "billing", Scope: "strict"},
	{Namespace: "dev-use1-green-apps", Name: "billing", Scope: "strict"},
	{Namespace: "dev-use2-blue-apps", Name: "billing", Scope: "strict"},
}

func TestOpenPullRequest(t *testing.T) {
	s, gh, _ := newService(t, nil)
	ctx := context.Background()
	_, head, err := s.Head(ctx, alice, "example-org", "apps", true)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := gh.mock.File("example-org", "apps", "main", "deploy/billing/sealed-secret.yaml")

	pr, err := s.OpenPullRequest(ctx, alice, "Example-Org", "apps", NewPullRequest{
		Commit: head, Branch: "sealer/dev/alice-1", Title: "Seal", Body: "body", Message: "Seal\n",
		Values: []Value{
			{Path: "deploy/billing/sealed-secret.yaml", Key: "api-token", Targets: billingTargets, Ciphertexts: []string{"AgA1", "AgA2", "AgA3"}},
			{Path: "deploy/billing/sealed-secret.yaml", Key: "db-password", Targets: billingTargets, Ciphertexts: []string{"AgB1", "AgB2", "AgB3"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if pr.Number != 1 || pr.Branch != "sealer/dev/alice-1" {
		t.Fatalf("pull request = %+v", pr)
	}
	view, _ := gh.mock.PullRequest("example-org", "apps", 1)
	if len(view.Files) != 1 || view.Files[0].Path != "deploy/billing/sealed-secret.yaml" || view.Base != "main" {
		t.Fatalf("pull request files = %+v", view)
	}
	// each dev document gets its own ciphertexts; nothing else changes
	want := before
	for _, n := range []string{"1", "2", "3"} {
		want = strings.Replace(want, "  encryptedData: {}\n",
			"  encryptedData:\n    api-token: AgA"+n+"\n    db-password: AgB"+n+"\n", 1)
	}
	if view.Files[0].After != want {
		t.Fatalf("file:\n%s\nwant:\n%s", view.Files[0].After, want)
	}
	docs, err := manifest.Find([]byte(view.Files[0].After), manifest.Annotations{Env: manifest.DefaultEnvAnnotation}, "dev")
	if err != nil || len(docs) != 3 || strings.Join(docs[2].Keys, ",") != "api-token,db-password" {
		t.Fatalf("documents after = %+v, %v", docs, err)
	}
}

func TestOpenPullRequest_Refuses(t *testing.T) {
	s, gh, _ := newService(t, nil)
	ctx := context.Background()
	_, head, err := s.Head(ctx, alice, "example-org", "apps", true)
	if err != nil {
		t.Fatal(err)
	}
	value := func(path string, targets []Target, n int) NewPullRequest {
		return NewPullRequest{
			Commit: head, Branch: "sealer/dev/x", Title: "t", Message: "m",
			Values: []Value{{Path: path, Key: "k", Targets: targets, Ciphertexts: make([]string, n)}},
		}
	}
	ciphertexts := func(pr NewPullRequest) NewPullRequest {
		for i := range pr.Values[0].Ciphertexts {
			pr.Values[0].Ciphertexts[i] = "AgA"
		}
		return pr
	}
	isFileError := func(err error) bool {
		var fe *FileError
		return errors.As(err, &fe)
	}
	unknownCommit := ciphertexts(value("deploy/billing/sealed-secret.yaml", billingTargets, 3))
	unknownCommit.Commit = strings.Repeat("0", 40)
	other := []Target{billingTargets[0], billingTargets[1], {Namespace: "x", Name: "billing", Scope: "strict"}}
	cases := map[string]struct {
		pr   NewPullRequest
		want func(error) bool
	}{
		"documents changed":     {ciphertexts(value("deploy/billing/sealed-secret.yaml", billingTargets[:2], 2)), isFileError},
		"another namespace":     {ciphertexts(value("deploy/billing/sealed-secret.yaml", other, 3)), isFileError},
		"too few ciphertexts":   {ciphertexts(value("deploy/billing/sealed-secret.yaml", billingTargets, 2)), isFileError},
		"cluster-wide document": {ciphertexts(value("deploy/legacy/sealed-secret.yaml", []Target{{Namespace: "legacy", Name: "legacy", Scope: "cluster-wide"}}, 1)), isFileError},
		"undiscovered file":     {ciphertexts(value("deploy/billing/deployment.yaml", billingTargets, 3)), isFileError},
		"unknown commit":        {unknownCommit, func(err error) bool { return errors.Is(err, ErrCommitNotFound) }},
		"no values":             {NewPullRequest{Commit: head, Branch: "sealer/dev/x", Title: "t", Message: "m"}, func(err error) bool { return err != nil }},
	}
	for name, tc := range cases {
		if _, err := s.OpenPullRequest(ctx, alice, "example-org", "apps", tc.pr); !tc.want(err) {
			t.Errorf("%s: %v", name, err)
		}
	}
	_, err = s.OpenPullRequest(ctx, alice, "example-org", "apps", ciphertexts(value("deploy/billing/sealed-secret.yaml", billingTargets[:2], 2)))
	if err == nil || !strings.Contains(err.Error(), "deploy/billing/sealed-secret.yaml: its documents for the dev env no longer match what k was sealed for; seal it again") {
		t.Errorf("message: %v", err)
	}
	good := ciphertexts(value("deploy/billing/sealed-secret.yaml", billingTargets, 3))
	if _, err := s.OpenPullRequest(ctx, bob, "example-org", "apps", good); !errors.Is(err, ErrForbidden) {
		t.Errorf("bob: %v", err)
	}
	if _, err := s.OpenPullRequest(ctx, carol, "example-org", "apps", good); !errors.Is(err, ErrNotFound) {
		t.Errorf("carol: %v", err)
	}
	if _, ok := gh.mock.PullRequest("example-org", "apps", 1); ok {
		t.Error("a refused request opened a pull request")
	}
	if _, err := s.OpenPullRequest(ctx, alice, "example-org", "apps", good); err != nil {
		t.Errorf("alice: %v", err)
	}
}

func TestOpenPullRequest_Regions(t *testing.T) {
	s, gh, _ := newService(t, nil)
	ctx := context.Background()
	_, head, err := s.Head(ctx, alice, "example-org", "apps", true)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := gh.mock.File("example-org", "apps", "main", "deploy/billing/sealed-secret.yaml")
	const path = "deploy/billing/sealed-secret.yaml"

	_, err = s.OpenPullRequest(ctx, alice, "example-org", "apps", NewPullRequest{
		Commit: head, Branch: "sealer/dev/alice-2", Title: "Seal", Message: "Seal\n",
		Values: []Value{
			// every document, then use1 again: use1 gets the later value
			{Path: path, Key: "api-token", Targets: billingTargets, Ciphertexts: []string{"AgA1", "AgA2", "AgA3"}},
			{Path: path, Key: "api-token", Regions: []string{"use1"}, Targets: billingTargets[:2], Ciphertexts: []string{"AgB1", "AgB2"}},
			// only use2
			{Path: path, Key: "db-password", Regions: []string{"use2"}, Targets: billingTargets[2:], Ciphertexts: []string{"AgC3"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	view, _ := gh.mock.PullRequest("example-org", "apps", 1)
	want := before
	for _, data := range []string{
		"    api-token: AgB1\n",
		"    api-token: AgB2\n",
		"    api-token: AgA3\n    db-password: AgC3\n",
	} {
		want = strings.Replace(want, "  encryptedData: {}\n", "  encryptedData:\n"+data, 1)
	}
	if view.Files[0].After != want {
		t.Fatalf("file:\n%s\nwant:\n%s", view.Files[0].After, want)
	}

	// a value's targets must be exactly its regions' documents
	for name, v := range map[string]Value{
		"more than the region": {Path: path, Key: "k", Regions: []string{"use1"}, Targets: billingTargets, Ciphertexts: []string{"AgA", "AgA", "AgA"}},
		"another region":       {Path: path, Key: "k", Regions: []string{"use2"}, Targets: billingTargets[:2], Ciphertexts: []string{"AgA", "AgA"}},
		"no such region":       {Path: path, Key: "k", Regions: []string{"use9"}, Targets: billingTargets[:1], Ciphertexts: []string{"AgA"}},
	} {
		_, err := s.OpenPullRequest(ctx, alice, "example-org", "apps", NewPullRequest{
			Commit: head, Branch: "sealer/dev/x", Title: "t", Message: "m", Values: []Value{v},
		})
		var fe *FileError
		if !errors.As(err, &fe) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
