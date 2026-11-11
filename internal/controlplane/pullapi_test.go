package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	ssv1alpha1 "github.com/bitnami/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	sscrypto "github.com/bitnami/sealed-secrets/pkg/crypto"
	"go.yaml.in/yaml/v3"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/mockgithub"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/registry"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/userauth"
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

// A change stored before regions were checked may name any region; its
// commit message must still hold only the lines the control plane writes.
func TestPullRequestText_KeepsRegionsOnOneLine(t *testing.T) {
	s := &Server{env: "dev"}
	text := s.pullRequestText(store.Session{Branch: "main", Commit: strings.Repeat("a", 40)},
		&userauth.User{ID: 1, Login: "alice"},
		[]store.Change{{Path: "apps/sealed.yaml", Key: "token", Fingerprint: "SHA256:x",
			Regions: []string{"use1)\n\nSigned-off-by: Mallory <m@example.com>\nCo-authored-by: x <x@example.com>\n(x"}}})
	for _, line := range strings.Split(text.message+"\n"+text.body, "\n") {
		if strings.HasPrefix(line, "Signed-off-by:") || strings.HasPrefix(line, "Co-authored-by:") {
			t.Fatalf("pull request text carries a forged line %q:\n%s\n\n%s", line, text.message, text.body)
		}
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
	changeURL := base + "/changes/" + changeID(billing, "api-token", nil)
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

	// GitHub fails: the session is unlocked again, to try once more
	sh.github.FailNext(http.MethodPost, "/git/trees", mockgithub.LoseAnswer)
	if code := sh.openPullRequest(sess.ID); code != http.StatusBadGateway {
		t.Fatalf("github failing = %d", code)
	}
	if got, ok, _ := sh.store.Session(ctx, user.ID, key, sh.clock()); !ok || got.Locked(sh.clock()) {
		t.Fatalf("session after a failed pull request = %+v, %v", got, ok)
	}
	if !strings.Contains(sh.logs.String(), "event=pr.failed") {
		t.Error("pr.failed was not logged")
	}
}

// A key revoked while values sealed with it wait in a session, or while a
// seal with it runs, never reaches a pull request: the values are sealed
// again with a new key first.
func TestPullRequest_RefusesValuesSealedWithARevokedKey(t *testing.T) {
	sh := newSealHarness(t)
	ctx := context.Background()
	sess := sh.openSession()
	sh.sealNow(sess.ID, billing, "api-token", "billing-s3cr3t")
	rec := sh.seal(sess.ID, search, "index-token", "search-s3cr3t")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("seal = %d %s", rec.Code, rec.Body)
	}
	queued := decode[sealView](t, rec)

	k, ok, err := sh.store.GetKey(ctx, sh.key.Fingerprint)
	if err != nil || !ok {
		t.Fatalf("key record: %v %v", ok, err)
	}
	at := sh.clock()
	k.Status, k.StatusBy, k.StatusAt = store.KeyRevoked, "carol", &at
	if ok, err := sh.store.SetKeyStatus(ctx, k); err != nil || !ok {
		t.Fatalf("revoke: %v %v", ok, err)
	}

	// the seal queued before the revocation fails, and makes no change; the
	// agent did its part, so its result is accepted
	sh.runAgent(queued.Agent.ID)
	if got := sh.sealStatus(sess.ID, queued.ID); got.Status != sealFailed || got.Error != "the key was revoked; seal the value again" {
		t.Fatalf("seal after the revocation = %+v", got)
	}
	session := *decode[sessionResponse](t, sh.do("alice", http.MethodGet, "/api/v1/repos/example-org/apps/session", nil, false)).Session
	if len(session.Changes) != 1 || session.Changes[0].Key != "api-token" || !session.Changes[0].KeyRevoked {
		t.Fatalf("changes = %+v", session.Changes)
	}

	// the change sealed earlier is refused, by name
	rec = sh.do("alice", http.MethodPost, "/api/v1/repos/example-org/apps/session/"+sess.ID+"/pull-request", nil, true)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "api-token in "+billing) {
		t.Fatalf("pull request = %d %s", rec.Code, rec.Body)
	}
	if _, opened := sh.github.PullRequest("example-org", "apps", 1); opened {
		t.Fatal("a pull request was opened")
	}

	// no key is left to seal with: a new one is needed, and seals say so
	if rec := sh.seal(sess.ID, billing, "api-token", "v"); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "a new key is needed") {
		t.Fatalf("seal with no usable key = %d %s", rec.Code, rec.Body)
	}
	if logs := sh.logs.String(); !strings.Contains(logs, "event=keys.out_of_sync") || !strings.Contains(logs, "reason=no_usable_key") {
		t.Error("keys.out_of_sync does not give the reason")
	}
	if got := decode[statusView](t, sh.do("alice", http.MethodGet, "/api/v1/status", nil, false)); got.Sealing != "unavailable" || !strings.Contains(got.Message, "a new key is needed") {
		t.Fatalf("status = %+v", got)
	}

	// with a new key in every cluster, the value sealed again goes through
	revokedKey := sh.key
	sh.key = newTestKey(t, time.Now().Add(-time.Minute))
	for _, id := range []string{"dev-use1-blue", "dev-use1-green", "dev-use2-blue"} {
		sh.checkIn(id, revokedKey.Key, sh.key.Key)
	}
	sh.sealNow(sess.ID, billing, "api-token", "billing-s3cr3t")
	if code := sh.openPullRequest(sess.ID); code != http.StatusCreated {
		t.Fatalf("pull request after sealing again = %d", code)
	}
}

func TestPullRequest_RetriesWhereGitHubActedButTheAnswerWasLost(t *testing.T) {
	for _, path := range []string{"/git/refs", "/pulls"} {
		t.Run(path, func(t *testing.T) {
			sh := newSealHarness(t)
			sess := sh.openSession()
			sh.sealNow(sess.ID, billing, "api-token", "v")
			sh.github.FailNext(http.MethodPost, path, mockgithub.LoseAnswer)
			if code := sh.openPullRequest(sess.ID); code != http.StatusBadGateway {
				t.Fatalf("first attempt = %d", code)
			}
			rec := sh.do("alice", http.MethodPost, "/api/v1/repos/example-org/apps/session/"+sess.ID+"/pull-request", nil, true)
			if rec.Code != http.StatusCreated || decode[pullRequestResponse](t, rec).PullRequest.Number != 1 {
				t.Fatalf("retry = %d %s", rec.Code, rec.Body)
			}
			view, ok := sh.github.PullRequest("example-org", "apps", 1)
			if !ok || view.State != "open" || len(view.Files) != 1 || view.Files[0].Path != billing {
				t.Fatalf("pull request = %+v", view)
			}
			if _, ok := sh.github.PullRequest("example-org", "apps", 2); ok {
				t.Fatal("a second pull request was opened")
			}
			if _, ok, _ := sh.store.Session(context.Background(), testUsers["alice"].ID, store.RepoKey("example-org", "apps"), sh.clock()); ok {
				t.Fatal("the session did not end")
			}
		})
	}
}

func TestPullRequest_UpdatesThePullRequestAnEarlierAttemptOpened(t *testing.T) {
	sh := newSealHarness(t)
	sess := sh.openSession()
	sh.sealNow(sess.ID, billing, "api-token", "v")
	// an attempt opened a pull request, but its answer was lost; the user
	// sealed another value before trying again
	sh.github.FailNext(http.MethodPost, "/pulls", mockgithub.LoseAnswer)
	if code := sh.openPullRequest(sess.ID); code != http.StatusBadGateway {
		t.Fatalf("first attempt = %d", code)
	}
	sh.sealNow(sess.ID, search, "index-token", "w")
	rec := sh.do("alice", http.MethodPost, "/api/v1/repos/example-org/apps/session/"+sess.ID+"/pull-request", nil, true)
	pr := decode[pullRequestResponse](t, rec).PullRequest
	if rec.Code != http.StatusCreated || pr.Number != 1 || pr.Changes != 2 {
		t.Fatalf("retry = %d %s", rec.Code, rec.Body)
	}
	view, _ := sh.github.PullRequest("example-org", "apps", 1)
	if len(view.Files) != 2 || view.Title != "Seal 2 values in 2 files for dev" || !strings.Contains(view.Body, "index-token") {
		t.Fatalf("pull request = %+v", view)
	}
}

func TestPullRequest_FitsTheRequestTimeLimit(t *testing.T) {
	// API Gateway, a Lambda function and the HTTP server all end a request
	// at 30 seconds; the pull request is made, and the session ended or
	// unlocked, well before
	if budget := pullRequestTimeout + pullRequestFinish; budget > 25*time.Second {
		t.Fatalf("a pull request may take %s", budget)
	}

	// reading the registry again takes none of that time: a read that does
	// not finish, as when SSM is slow, does not hold the pull request up
	sh := newSealHarness(t)
	sess := sh.openSession()
	sh.sealNow(sess.ID, billing, "api-token", "v")
	reading := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	sh.mu.Lock()
	sh.reload = func(ctx context.Context) (*registry.Registry, map[string]LoginVerifier, error) {
		close(reading)
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil, nil, ctx.Err()
	}
	sh.mu.Unlock()
	sh.advance(RegistryReloadInterval)
	start := time.Now()
	if code := sh.openPullRequest(sess.ID); code != http.StatusCreated {
		t.Fatalf("pull request = %d", code)
	}
	select {
	case <-reading:
	default:
		t.Fatal("the pull request did not start reading the registry")
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("the pull request took %s, waiting on the registry", took)
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
			SessionID: sess.ID, ID: changeID(billing, k, nil), Path: billing, Key: k, CommandID: "01J0000000000000000000000" + string(rune('A'+i%26)),
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

// Seals still running count toward the cap: their changes have not landed
// yet, and requests in quick succession must not each see room for one.
func TestSeal_CapCountsSealsInFlight(t *testing.T) {
	sh := newSealHarness(t)
	ctx := context.Background()
	sess := sh.openSession()
	stored, _, _ := sh.store.Session(ctx, testUsers["alice"].ID, store.RepoKey("example-org", "apps"), sh.clock())
	for i := range maxChangesPerSession - 1 {
		k := fmt.Sprintf("key-%d", i)
		_, err := sh.store.PutChange(ctx, store.Change{
			SessionID: sess.ID, ID: changeID(billing, k, nil), Path: billing, Key: k, CommandID: "01J0000000000000000000000" + string(rune('A'+i%26)),
			ExpiresAt: stored.EndsAt,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if rec := sh.seal(sess.ID, billing, "last", "v"); rec.Code != http.StatusAccepted {
		t.Fatalf("seal of the last change = %d %s", rec.Code, rec.Body)
	}
	if rec := sh.seal(sess.ID, billing, "one-more", "v"); rec.Code != http.StatusConflict {
		t.Fatalf("seal past the cap while the last is running = %d %s", rec.Code, rec.Body)
	}
	// the last seal expires without a result, and its place is free again
	sh.advance(sealChangeHold + time.Second)
	for id := range sh.agents {
		sh.checkIn(id, sh.key.Key)
	}
	if rec := sh.seal(sess.ID, billing, "one-more", "v"); rec.Code != http.StatusAccepted {
		t.Fatalf("seal after the last expired = %d %s", rec.Code, rec.Body)
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

// sealNowIn seals a value for the documents in some regions and runs the
// agent that was sent it.
func (sh *sealHarness) sealNowIn(sessionID, path, key, value string, regions ...string) sealView {
	sh.t.Helper()
	rec := sh.do("alice", http.MethodPost, "/api/v1/repos/example-org/apps/session/"+sessionID+"/seals",
		map[string]any{"path": path, "key": key, "value": value, "regions": regions}, true)
	if rec.Code != http.StatusAccepted {
		sh.t.Fatalf("seal %s in %v = %d %s", key, regions, rec.Code, rec.Body)
	}
	seal := decode[sealView](sh.t, rec)
	sh.runAgent(seal.Agent.ID)
	if got := sh.sealStatus(sessionID, seal.ID); got.Status != sealSealed {
		sh.t.Fatalf("seal %s = %+v", key, got)
	}
	return seal
}

func TestRegionSeals(t *testing.T) {
	sh := newSealHarness(t)
	sess := sh.openSession()
	base := "/api/v1/repos/example-org/apps/session/" + sess.ID
	changes := func() []changeView {
		t.Helper()
		rec := sh.do("alice", http.MethodGet, "/api/v1/repos/example-org/apps/session", nil, false)
		return decode[sessionResponse](t, rec).Session.Changes
	}

	// regions must be ones the file's documents are in
	for _, regions := range [][]string{{"use9"}, {""}, {"use1", "use9"}} {
		rec := sh.do("alice", http.MethodPost, base+"/seals",
			map[string]any{"path": billing, "key": "k", "value": "v", "regions": regions}, true)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("regions %q = %d %s", regions, rec.Code, rec.Body)
		}
	}

	// a value for every document, then another for use1: use1 gets the
	// newer one, use2 keeps the first
	sh.sealNow(sess.ID, billing, "api-token", "everywhere-s3cr3t")
	seal := sh.sealNowIn(sess.ID, billing, "api-token", "use1-s3cr3t", "use1")
	if !slices.Equal(seal.Regions, []string{"use1"}) || len(seal.Targets) != 2 || seal.Agent.Region != "use1" {
		t.Fatalf("seal for use1 = %+v", seal)
	}
	sh.sealNowIn(sess.ID, billing, "db-password", "use2-db-s3cr3t", "use2")
	got := changes()
	if len(got) != 3 ||
		got[0].Key != "api-token" || got[0].Regions != nil || len(got[0].Targets) != 1 || got[0].Targets[0].Region != "use2" ||
		got[1].Key != "api-token" || !slices.Equal(got[1].Regions, []string{"use1"}) || len(got[1].Targets) != 2 ||
		got[2].Key != "db-password" || !slices.Equal(got[2].Regions, []string{"use2"}) {
		t.Fatalf("changes = %+v", got)
	}

	// naming every region is sealing for every document, and replaces what
	// it covers
	seal = sh.sealNowIn(sess.ID, billing, "smtp", "a", "use2")
	seal = sh.sealNowIn(sess.ID, billing, "smtp", "b", "use2", "use1", "use1")
	if seal.Regions != nil || len(seal.Targets) != 3 {
		t.Fatalf("seal for every region = %+v", seal)
	}
	stored, _ := sh.store.Changes(context.Background(), sess.ID, false)
	smtp := 0
	for _, c := range stored {
		if c.Key == "smtp" {
			smtp++
			if c.ID != changeID(billing, "smtp", nil) {
				t.Errorf("smtp change = %+v", c)
			}
		}
	}
	if smtp != 1 || len(changes()) != 4 {
		t.Fatalf("the covered change was kept: %+v", stored)
	}
	if rec := sh.do("alice", http.MethodDelete, base+"/changes/"+changeID(billing, "smtp", nil), nil, true); rec.Code != http.StatusNoContent {
		t.Fatalf("remove smtp = %d", rec.Code)
	}

	if code := sh.openPullRequest(sess.ID); code != http.StatusCreated {
		t.Fatalf("pull request = %d", code)
	}
	view, _ := sh.github.PullRequest("example-org", "apps", 1)
	docs := encryptedData(t, view.Files[0].After)
	namespaces := []string{"dev-use1-blue-apps", "dev-use1-green-apps", "dev-use2-blue-apps"}
	decrypt := func(i int, key string) string {
		t.Helper()
		raw, err := base64.StdEncoding.DecodeString(docs[i][key])
		if err != nil {
			t.Fatalf("%s in %s: %v", key, namespaces[i], err)
		}
		plain, err := sscrypto.HybridDecrypt(rand.Reader, map[string]*rsa.PrivateKey{"": sh.keyPriv}, raw,
			ssv1alpha1.EncryptionLabel(namespaces[i], "billing", ssv1alpha1.StrictScope))
		if err != nil {
			t.Fatalf("%s in %s: %v", key, namespaces[i], err)
		}
		return string(plain)
	}
	if decrypt(0, "api-token") != "use1-s3cr3t" || decrypt(1, "api-token") != "use1-s3cr3t" ||
		decrypt(2, "api-token") != "everywhere-s3cr3t" || decrypt(2, "db-password") != "use2-db-s3cr3t" {
		t.Fatal("values are not in their regions' documents")
	}
	if _, ok := docs[0]["db-password"]; ok {
		t.Fatal("db-password was written outside use2")
	}
	if !strings.Contains(view.Body, "| `deploy/billing/sealed-secret.yaml` | `api-token` in `use1` | `dev-use1-blue-apps/billing`, `dev-use1-green-apps/billing` |") ||
		!strings.Contains(view.Body, "| `deploy/billing/sealed-secret.yaml` | `api-token` | `dev-use2-blue-apps/billing` |") ||
		!strings.Contains(view.Body, "or those in the regions named") {
		t.Fatalf("body:\n%s", view.Body)
	}
	if !strings.Contains(view.Message, "deploy/billing/sealed-secret.yaml: api-token, api-token (use1), db-password (use2)\n") {
		t.Fatalf("commit message:\n%s", view.Message)
	}
}

// regional is a file with one copy of a secret per region, each in the
// same namespace and with the same name, as in clusters of their own.
const regional = "deploy/regional/sealed-secret.yaml"

const regionalFile = `apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: payments
  namespace: apps
  annotations:
    k8s-sealed-secrets-sealer/env: dev
    k8s-sealed-secrets-sealer/region: use1
spec:
  encryptedData: {}
---
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: payments
  namespace: apps
  annotations:
    k8s-sealed-secrets-sealer/env: dev
    k8s-sealed-secrets-sealer/region: use2
spec:
  encryptedData: {}
`

func TestRegionSeals_SameNameInEachRegion(t *testing.T) {
	sh := newSealHarness(t, map[string]string{regional: regionalFile})
	sess := sh.openSession()
	base := "/api/v1/repos/example-org/apps/session/" + sess.ID
	changes := func() []changeView {
		t.Helper()
		rec := sh.do("alice", http.MethodGet, "/api/v1/repos/example-org/apps/session", nil, false)
		return decode[sessionResponse](t, rec).Session.Changes
	}
	regionsOf := func(cs []changeView, key string) [][]string {
		var out [][]string
		for _, c := range cs {
			if c.Key != key {
				continue
			}
			var regions []string
			for _, t := range c.Targets {
				regions = append(regions, t.Region)
			}
			out = append(out, regions)
		}
		return out
	}

	// a value for each region: both stay pending
	sh.sealNowIn(sess.ID, regional, "token", "use1-token", "use1")
	sh.sealNowIn(sess.ID, regional, "token", "use2-token", "use2")
	if got := regionsOf(changes(), "token"); !reflect.DeepEqual(got, [][]string{{"use1"}, {"use2"}}) {
		t.Fatalf("token changes = %v", got)
	}

	// every region, then each region: the first stays, since removing a
	// newer one brings it back where that one applied
	sh.sealNowIn(sess.ID, regional, "password", "everywhere", "use1", "use2")
	sh.sealNowIn(sess.ID, regional, "password", "use1-password", "use1")
	use2 := sh.sealNowIn(sess.ID, regional, "password", "use2-password", "use2")
	if got := regionsOf(changes(), "password"); !reflect.DeepEqual(got, [][]string{{"use1"}, {"use2"}}) {
		t.Fatalf("password changes = %v", got)
	}
	stored, _ := sh.store.Changes(context.Background(), sess.ID, false)
	if len(stored) != 5 {
		t.Fatalf("stored changes = %d, want 5", len(stored))
	}
	if rec := sh.do("alice", http.MethodDelete, base+"/changes/"+changeID(regional, "password", use2.Regions), nil, true); rec.Code != http.StatusNoContent {
		t.Fatalf("remove use2 password = %d %s", rec.Code, rec.Body)
	}
	if got := regionsOf(changes(), "password"); !reflect.DeepEqual(got, [][]string{{"use2"}, {"use1"}}) {
		t.Fatalf("password changes after removing use2's = %v", got)
	}

	// a seal one newer seal covers is no longer pending
	first := sh.sealNowIn(sess.ID, regional, "url", "one", "use1")
	sh.sealNowIn(sess.ID, regional, "url", "everywhere", "use1", "use2")
	if got := sh.sealStatus(sess.ID, first.ID); got.Status != sealSuperseded || got.ChangeID != "" {
		t.Fatalf("status of a covered seal = %+v", got)
	}
	if got := regionsOf(changes(), "url"); !reflect.DeepEqual(got, [][]string{{"use1", "use2"}}) {
		t.Fatalf("url changes = %v", got)
	}

	if code := sh.openPullRequest(sess.ID); code != http.StatusCreated {
		t.Fatalf("pull request = %d", code)
	}
	view, _ := sh.github.PullRequest("example-org", "apps", 1)
	var after string
	for _, f := range view.Files {
		if f.Path == regional {
			after = f.After
		}
	}
	docs := encryptedData(t, after)
	decrypt := func(i int, key string) string {
		t.Helper()
		raw, err := base64.StdEncoding.DecodeString(docs[i][key])
		if err != nil {
			t.Fatalf("%s in document %d: %v", key, i, err)
		}
		plain, err := sscrypto.HybridDecrypt(rand.Reader, map[string]*rsa.PrivateKey{"": sh.keyPriv}, raw,
			ssv1alpha1.EncryptionLabel("apps", "payments", ssv1alpha1.StrictScope))
		if err != nil {
			t.Fatalf("%s in document %d: %v", key, i, err)
		}
		return string(plain)
	}
	for _, c := range []struct {
		doc       int
		key, want string
	}{
		{0, "token", "use1-token"}, {1, "token", "use2-token"},
		{0, "password", "use1-password"}, {1, "password", "everywhere"},
		{0, "url", "everywhere"}, {1, "url", "everywhere"},
	} {
		if got := decrypt(c.doc, c.key); got != c.want {
			t.Errorf("%s in document %d = %q, want %q", c.key, c.doc, got, c.want)
		}
	}
}
