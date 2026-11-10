package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	ssv1alpha1 "github.com/bitnami/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	sscrypto "github.com/bitnami/sealed-secrets/pkg/crypto"
	"go.yaml.in/yaml/v3"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/githubapp"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
)

const search = "deploy/search/sealed-secret.yaml"

type pullRequestResponse struct {
	PullRequest pullRequestView `json:"pull_request"`
}

// sealNow seals a value and runs the agent that was sent it.
func (sh *sealHarness) sealNow(sessionID, path, key, value string) sealView {
	sh.t.Helper()
	rec := sh.seal(sessionID, path, key, value)
	if rec.Code != http.StatusAccepted {
		sh.t.Fatalf("seal %s = %d %s", key, rec.Code, rec.Body)
	}
	seal := decode[sealView](sh.t, rec)
	sh.runAgent(seal.Agent.ID)
	if got := sh.sealStatus(sessionID, seal.ID); got.Status != sealSealed {
		sh.t.Fatalf("seal %s = %+v", key, got)
	}
	return seal
}

func (sh *sealHarness) openPullRequest(sessionID string) int {
	sh.t.Helper()
	return sh.do("alice", http.MethodPost, "/api/v1/repos/example-org/apps/session/"+sessionID+"/pull-request", nil, true).Code
}

// encryptedData reads spec.encryptedData of each document in a file.
func encryptedData(t *testing.T, content string) []map[string]string {
	t.Helper()
	dec := yaml.NewDecoder(strings.NewReader(content))
	var out []map[string]string
	for {
		var doc struct {
			Metadata struct {
				Namespace   string            `yaml:"namespace"`
				Annotations map[string]string `yaml:"annotations"`
			} `yaml:"metadata"`
			Spec struct {
				EncryptedData map[string]string `yaml:"encryptedData"`
			} `yaml:"spec"`
		}
		if err := dec.Decode(&doc); err != nil {
			break
		}
		if doc.Metadata.Annotations["k8s-sealed-secrets-sealer/env"] == "dev" {
			out = append(out, doc.Spec.EncryptedData)
		}
	}
	return out
}

func TestPullRequestFlow(t *testing.T) {
	sh := newSealHarness(t)
	sess := sh.openSession()
	sh.sealNow(sess.ID, billing, "api-token", "billing-s3cr3t")
	sh.sealNow(sess.ID, search, "index-token", "search-s3cr3t")
	sh.sealNow(sess.ID, search, "admin-token", "admin-s3cr3t")
	base := "/api/v1/repos/example-org/apps/session/" + sess.ID

	if rec := sh.do("alice", http.MethodPost, base+"/pull-request", nil, false); rec.Code != http.StatusForbidden {
		t.Fatalf("without csrf = %d", rec.Code)
	}
	if rec := sh.do("bob", http.MethodPost, base+"/pull-request", nil, true); rec.Code != http.StatusNotFound {
		t.Fatalf("bob = %d", rec.Code)
	}

	rec := sh.do("alice", http.MethodPost, base+"/pull-request", nil, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("pull request = %d %s", rec.Code, rec.Body)
	}
	pr := decode[pullRequestResponse](t, rec).PullRequest
	wantBranch := "sealer/dev/alice-" + strings.ToLower(sess.ID)
	if pr.Number != 1 || !strings.HasSuffix(pr.URL, "/example-org/apps/pull/1") || pr.Branch != wantBranch ||
		pr.Files != 2 || pr.Changes != 3 || pr.Title != "Seal 3 values in 2 files for dev" {
		t.Fatalf("pull request = %+v", pr)
	}

	view, ok := sh.github.PullRequest("example-org", "apps", 1)
	if !ok || view.Base != "main" || view.Head != wantBranch || len(view.Commits) != 1 || len(view.Files) != 2 {
		t.Fatalf("pull request in GitHub = %+v", view)
	}
	stored := map[string]bool{}
	for _, f := range view.Files {
		for _, data := range encryptedData(t, f.After) {
			for _, ct := range data {
				stored[ct] = true
			}
		}
	}
	// every dev document decrypts, under its own label, to its value
	check := func(content, key, value string, namespaces []string, scope ssv1alpha1.SealingScope, name string) {
		t.Helper()
		docs := encryptedData(t, content)
		if len(docs) != len(namespaces) {
			t.Fatalf("%d dev documents, want %d", len(docs), len(namespaces))
		}
		for i, data := range docs {
			raw, err := base64.StdEncoding.DecodeString(data[key])
			if err != nil {
				t.Fatalf("%s in document %d: %v", key, i, err)
			}
			label := ssv1alpha1.EncryptionLabel(namespaces[i], name, scope)
			plain, err := sscrypto.HybridDecrypt(rand.Reader, map[string]*rsa.PrivateKey{"": sh.keyPriv}, raw, label)
			if err != nil || string(plain) != value {
				t.Fatalf("%s in %s/%s = %q, %v", key, namespaces[i], name, plain, err)
			}
		}
	}
	billingFile, searchFile := view.Files[0], view.Files[1]
	check(billingFile.After, "api-token", "billing-s3cr3t",
		[]string{"dev-use1-blue-apps", "dev-use1-green-apps", "dev-use2-blue-apps"}, ssv1alpha1.StrictScope, "billing")
	check(searchFile.After, "index-token", "search-s3cr3t", []string{"dev-use1-blue-apps"}, ssv1alpha1.NamespaceWideScope, "search")
	check(searchFile.After, "admin-token", "admin-s3cr3t", []string{"dev-use1-blue-apps"}, ssv1alpha1.NamespaceWideScope, "search")

	// only encryptedData lines changed: the comment and the prod document
	// are kept as they were
	if !strings.Contains(searchFile.After, "    # may be renamed within its namespace\n") ||
		strings.Count(billingFile.After, "\n") != strings.Count(billingFile.Before, "\n")+3 ||
		!strings.Contains(billingFile.After, "    api-key: AgBplaceholderProdCiphertext") {
		t.Fatalf("billing file:\n%s", billingFile.After)
	}

	// title, description and commit name files, keys and the requester;
	// never values or ciphertexts
	if !strings.Contains(view.Body, "@alice") || !strings.Contains(view.Body, "| `deploy/search/sealed-secret.yaml` | `admin-token` | `dev-use1-blue-apps/search` |") {
		t.Fatalf("body:\n%s", view.Body)
	}
	wantMessage := "Seal 3 values in 2 files for dev\n\n" +
		"deploy/billing/sealed-secret.yaml: api-token\n" +
		"deploy/search/sealed-secret.yaml: admin-token, index-token\n\n" +
		"Requested-by: alice <1001+alice@users.noreply.github.com>\n"
	if view.Message != wantMessage {
		t.Fatalf("commit message:\n%s", view.Message)
	}
	for ct := range stored {
		if strings.Contains(view.Body+view.Message+view.Title, ct[:32]) || strings.Contains(rec.Body.String(), ct[:32]) {
			t.Fatal("a ciphertext is in the pull request's text or the response")
		}
	}
	for _, v := range []string{"billing-s3cr3t", "search-s3cr3t", "admin-s3cr3t"} {
		if strings.Contains(view.Body+view.Message+sh.logs.String(), v) {
			t.Fatalf("value %s leaked", v)
		}
	}
	if !strings.Contains(sh.logs.String(), "event=pr.opened") {
		t.Error("pr.opened was not logged")
	}

	// the session ended
	rec = sh.do("alice", http.MethodGet, "/api/v1/repos/example-org/apps/session", nil, false)
	if decode[sessionResponse](t, rec).Session != nil {
		t.Fatalf("session after the pull request = %s", rec.Body)
	}
	if rec := sh.do("alice", http.MethodPost, base+"/pull-request", nil, true); rec.Code != http.StatusNotFound {
		t.Fatalf("second pull request = %d %s", rec.Code, rec.Body)
	}
}

func TestPullRequestText_OneChange(t *testing.T) {
	sh := newSealHarness(t)
	sess := sh.openSession()
	sh.sealNow(sess.ID, billing, "api-token", "v")
	if code := sh.openPullRequest(sess.ID); code != http.StatusCreated {
		t.Fatalf("pull request = %d", code)
	}
	view, _ := sh.github.PullRequest("example-org", "apps", 1)
	if view.Title != "Seal api-token in deploy/billing/sealed-secret.yaml for dev" {
		t.Fatalf("title = %q", view.Title)
	}
	if !strings.Contains(view.Body, "Based on `main` at "+sess.Commit) {
		t.Fatalf("body:\n%s", view.Body)
	}
}

func TestPullRequest_Refuses(t *testing.T) {
	sh := newSealHarness(t)
	ctx := context.Background()
	sess := sh.openSession()
	base := "/api/v1/repos/example-org/apps/session/" + sess.ID
	user := testUsers["alice"]
	key := store.RepoKey("example-org", "apps")

	// nothing to open
	if code := sh.openPullRequest(sess.ID); code != http.StatusConflict {
		t.Fatalf("no changes = %d", code)
	}

	// a seal still running would be left out
	rec := sh.seal(sess.ID, billing, "api-token", "v")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("seal = %d %s", rec.Code, rec.Body)
	}
	running := decode[sealView](t, rec)
	if code := sh.openPullRequest(sess.ID); code != http.StatusConflict {
		t.Fatalf("with a seal running = %d", code)
	}
	sh.runAgent(running.Agent.ID)

	// while a pull request is opened, the session cannot change
	now := sh.clock()
	if ok, err := sh.store.LockSession(ctx, user.ID, key, sess.ID, now.Add(pullRequestLock), now); err != nil || !ok {
		t.Fatalf("lock: %v %v", ok, err)
	}
	if rec := sh.seal(sess.ID, billing, "other", "v"); rec.Code != http.StatusConflict {
		t.Fatalf("seal while locked = %d %s", rec.Code, rec.Body)
	}
	changeURL := base + "/changes/" + changeID(billing, "api-token")
	if rec := sh.do("alice", http.MethodDelete, changeURL, nil, true); rec.Code != http.StatusConflict {
		t.Fatalf("remove while locked = %d", rec.Code)
	}
	if rec := sh.do("alice", http.MethodDelete, base, nil, true); rec.Code != http.StatusConflict {
		t.Fatalf("discard while locked = %d", rec.Code)
	}
	if code := sh.openPullRequest(sess.ID); code != http.StatusConflict {
		t.Fatalf("second pull request while locked = %d", code)
	}
	// a lock lapses
	sh.advance(pullRequestLock + time.Second)

	// the branch already exists: GitHub refuses, nothing is opened twice,
	// and the session is unlocked again
	head := sess.Commit
	_, err := sh.app.CreatePullRequest(ctx, "example-org", "apps", githubapp.NewPullRequest{
		Base: "main", Parent: head, Branch: pullRequestBranch("dev", "alice", sess.ID), Message: "m", Title: "t",
		Files: []githubapp.FileChange{{Path: "x.yaml", Mode: "100644", Content: []byte("x\n")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if code := sh.openPullRequest(sess.ID); code != http.StatusBadGateway {
		t.Fatalf("existing branch = %d", code)
	}
	if _, ok := sh.github.PullRequest("example-org", "apps", 2); ok {
		t.Fatal("a second pull request was opened")
	}
	if got, ok, _ := sh.store.Session(ctx, user.ID, key, sh.clock()); !ok || got.Locked(sh.clock()) {
		t.Fatalf("session after a failed pull request = %+v, %v", got, ok)
	}
	if !strings.Contains(sh.logs.String(), "event=pr.failed") {
		t.Error("pr.failed was not logged")
	}
}

func TestPullRequest_RefusesAChangeTheFileNoLongerMatches(t *testing.T) {
	sh := newSealHarness(t)
	ctx := context.Background()
	sess := sh.openSession()
	sh.sealNow(sess.ID, billing, "api-token", "v")
	changes, _ := sh.store.Changes(ctx, sess.ID, true)
	c := changes[0]
	c.Targets, c.Ciphertexts = c.Targets[:2], c.Ciphertexts[:2]
	c.CommandID = "02" + c.CommandID[2:] // newer, so it replaces the change
	if ok, err := sh.store.PutChange(ctx, c); err != nil || !ok {
		t.Fatalf("put change: %v %v", ok, err)
	}
	rec := sh.do("alice", http.MethodPost, "/api/v1/repos/example-org/apps/session/"+sess.ID+"/pull-request", nil, true)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "seal it again") {
		t.Fatalf("pull request = %d %s", rec.Code, rec.Body)
	}
	if _, ok, _ := sh.store.Session(ctx, testUsers["alice"].ID, store.RepoKey("example-org", "apps"), sh.clock()); !ok {
		t.Fatal("the session ended")
	}
}

func TestSeal_CapsPendingChanges(t *testing.T) {
	sh := newSealHarness(t)
	ctx := context.Background()
	sess := sh.openSession()
	stored, _, _ := sh.store.Session(ctx, testUsers["alice"].ID, store.RepoKey("example-org", "apps"), sh.clock())
	for i := range maxChangesPerSession {
		k := fmt.Sprintf("key-%d", i)
		_, err := sh.store.PutChange(ctx, store.Change{
			SessionID: sess.ID, ID: changeID(billing, k), Path: billing, Key: k, CommandID: "01J0000000000000000000000" + string(rune('A'+i%26)),
			ExpiresAt: stored.EndsAt,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if rec := sh.seal(sess.ID, billing, "one-more", "v"); rec.Code != http.StatusConflict {
		t.Fatalf("seal past the cap = %d %s", rec.Code, rec.Body)
	}
	// sealing a key again replaces its change, so it is allowed
	if rec := sh.seal(sess.ID, billing, "key-7", "v"); rec.Code != http.StatusAccepted {
		t.Fatalf("reseal at the cap = %d %s", rec.Code, rec.Body)
	}
}

func TestStatus(t *testing.T) {
	sh := newSealHarness(t)
	status := func() statusView {
		t.Helper()
		rec := sh.do("alice", http.MethodGet, "/api/v1/status", nil, false)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d %s", rec.Code, rec.Body)
		}
		return decode[statusView](t, rec)
	}
	if got := status(); got.Sealing != "ready" || got.Clusters.Ready != 3 || got.Clusters.Total != 3 {
		t.Fatalf("status = %+v", got)
	}
	// one cluster stops checking in: sealing still works
	sh.advance(time.Hour)
	sh.checkIn("dev-use1-blue", sh.key.Key)
	sh.checkIn("dev-use1-green", sh.key.Key)
	if got := status(); got.Sealing != "degraded" || got.Clusters.Ready != 2 || !strings.Contains(got.Message, "1 of 3") {
		t.Fatalf("status = %+v", got)
	}
}
