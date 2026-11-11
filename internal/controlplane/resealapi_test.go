package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	ssv1alpha1 "github.com/bitnami/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	sscrypto "github.com/bitnami/sealed-secrets/pkg/crypto"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/agent"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
)

const resealPath = "deploy/reseal/sealed-secret.yaml"

// resealCaps are what agents need to reseal.
var resealCaps = []string{protocol.CapabilitySeal, protocol.CapabilityKeys, protocol.CapabilityReseal}

// resealFixture is a file of three dev documents, one per simulated
// cluster: old-token sealed with an older key, current-token with the env
// key, and in the first, a value no key opens.
type resealFixture struct {
	sh      *sealHarness
	old     testKey
	oldPriv *rsa.PrivateKey
	// values holds old-token's value in each document
	values []string
}

func privateKey(t *testing.T, k testKey) *rsa.PrivateKey {
	t.Helper()
	block, _ := pem.Decode(k.PrivatePEM)
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

// sealFor seals value with a key's public key, as kubeseal does, for a
// strict-scope SealedSecret.
func sealFor(t *testing.T, priv *rsa.PrivateKey, namespace, name, value string) string {
	t.Helper()
	ct, err := sscrypto.HybridEncrypt(rand.Reader, &priv.PublicKey, []byte(value), ssv1alpha1.EncryptionLabel(namespace, name, ssv1alpha1.StrictScope))
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(ct)
}

func newResealFixture(t *testing.T) *resealFixture {
	t.Helper()
	old := newTestKey(t, time.Now().Add(-90*24*time.Hour))
	oldPriv := privateKey(t, old)
	sh := newSealHarnessWith(t, resealCaps)
	sh.admins["alice"] = true
	f := &resealFixture{sh: sh, old: old, oldPriv: oldPriv}
	var b strings.Builder
	for i, doc := range []struct{ ns, region string }{
		{"dev-use1-blue-apps", "use1"}, {"dev-use1-green-apps", "use1"}, {"dev-use2-blue-apps", "use2"},
	} {
		value := fmt.Sprintf("old-value-%d", i)
		f.values = append(f.values, value)
		fmt.Fprintf(&b, "---\napiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nmetadata:\n  name: reseal\n  namespace: %s\n  annotations:\n"+
			"    k8s-sealed-secrets-sealer/env: dev\n    k8s-sealed-secrets-sealer/region: %s\nspec:\n  encryptedData:\n"+
			"    current-token: %s\n    old-token: %s\n", doc.ns, doc.region,
			sealFor(t, sh.keyPriv, doc.ns, "reseal", "current"), sealFor(t, oldPriv, doc.ns, "reseal", value))
		if i == 0 {
			b.WriteString("    bad: AgBplaceholderDevCiphertext00000000000000000000000000000000000==\n")
		}
	}
	if _, ok := sh.github.Push("example-org", "apps", "main", "mock", map[string]string{resealPath: b.String()}); !ok {
		t.Fatal("push")
	}
	f.checkInAll()
	return f
}

// checkInAll checks every agent in, each holding the older key and the env
// key, the newer.
func (f *resealFixture) checkInAll() {
	f.sh.t.Helper()
	for id := range f.sh.agents {
		f.sh.checkIn(id, f.old.Key, f.sh.key.Key)
	}
}

// runResealer leases an agent's commands and runs them as the agent would,
// with key Secrets for the keys given, reporting each result.
func (sh *sealHarness) runResealer(id string, held ...testKey) []protocol.CommandResult {
	sh.t.Helper()
	rec := sh.agentDo(http.MethodGet, "/agent/v1/commands?wait=0", id, nil)
	if rec.Code != http.StatusOK {
		sh.t.Fatalf("poll %s = %d %s", id, rec.Code, rec.Body)
	}
	var objs []runtime.Object
	var set []protocol.Key
	for i, k := range held {
		objs = append(objs, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("key-%d", i), Namespace: "sealed-secrets",
				Labels: map[string]string{"sealedsecrets.bitnami.com/sealed-secrets-key": "active"}},
			Data: map[string][]byte{"tls.crt": []byte(k.Certificate), "tls.key": k.PrivatePEM},
		})
		set = append(set, k.Key)
	}
	// its controller seals with the env key, the harness's
	resealer := agent.NewResealer(agent.ResealerOptions{
		Keys: activeKeys{keys: set, active: sh.key.Fingerprint}, Kube: fake.NewClientset(objs...), Namespace: "sealed-secrets", Env: "dev",
		Logger: slog.New(slog.DiscardHandler),
	})
	var results []protocol.CommandResult
	for _, cmd := range decode[protocol.CommandsResponse](sh.t, rec).Commands {
		if cmd.Type != protocol.CommandReseal {
			sh.t.Fatalf("%s was sent %s", id, cmd.Type)
		}
		res := protocol.CommandResult{Status: protocol.CommandSucceeded}
		out, err := resealer.Reseal(context.Background(), cmd)
		if err != nil {
			res = protocol.CommandResult{Status: protocol.CommandFailed, Error: err.Error()}
		} else {
			res.Result, _ = json.Marshal(out)
		}
		if rec := sh.agentDo(http.MethodPost, "/agent/v1/commands/"+cmd.ID+"/result", id, res); rec.Code != http.StatusOK {
			sh.t.Fatalf("result = %d %s", rec.Code, rec.Body)
		}
		results = append(results, res)
	}
	return results
}

// activeKeys is a controller's key set and the key it seals with.
type activeKeys struct {
	keys   []protocol.Key
	active string
}

func (k activeKeys) Collect(context.Context) (agent.Report, error) {
	return agent.Report{Controller: protocol.Controller{ActiveFingerprint: k.active}, Keys: k.keys, Complete: true}, nil
}

func (sh *sealHarness) reseal(login, sessionID, path string) *httptest.ResponseRecorder {
	sh.t.Helper()
	return sh.do(login, http.MethodPost, "/api/v1/repos/example-org/apps/session/"+sessionID+"/reseals", map[string]string{"path": path}, true)
}

func (sh *sealHarness) resealStatus(sessionID, id string) fileResealView {
	sh.t.Helper()
	rec := sh.do("alice", http.MethodGet, "/api/v1/repos/example-org/apps/session/"+sessionID+"/reseals/"+id, nil, false)
	if rec.Code != http.StatusOK {
		sh.t.Fatalf("reseal status = %d %s", rec.Code, rec.Body)
	}
	return decode[fileResealView](sh.t, rec)
}

func TestResealFile(t *testing.T) {
	f := newResealFixture(t)
	sh := f.sh
	ctx := context.Background()
	sess := sh.openSession()

	// a value sealed in the session is never replaced by a reseal: use2's
	// old-token has a pending change, so it is left out
	rec := sh.do("alice", http.MethodPost, "/api/v1/repos/example-org/apps/session/"+sess.ID+"/seals",
		map[string]any{"path": resealPath, "key": "old-token", "value": "new-in-use2", "regions": []string{"use2"}}, true)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("regional seal = %d %s", rec.Code, rec.Body)
	}
	regional := decode[sealView](t, rec)
	sh.runAgent(regional.Agent.ID)

	rec = sh.reseal("alice", sess.ID, resealPath)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("reseal = %d %s", rec.Code, rec.Body)
	}
	queued := decode[fileResealView](t, rec)
	if queued.Status != resealQueued || queued.Values.Total != 7 || queued.Values.Pending != 1 || queued.Agent == nil || queued.Agent.Region != "use1" {
		t.Fatalf("queued = %+v", queued)
	}
	// the values are stored apart from the agent's commands, and never
	// logged
	cmd, found, _ := sh.store.Command(ctx, queued.Agent.ID, latestCommand(t, sh, queued.Agent.ID))
	if !found || cmd.Payload != "" || !cmd.ExternalPayload || cmd.ResealID != queued.ID || cmd.SessionID != sess.ID {
		t.Fatalf("command = %+v", cmd)
	}

	results := sh.runResealer(queued.Agent.ID, f.old, sh.key)
	if len(results) != 1 || results[0].Status != protocol.CommandSucceeded {
		t.Fatalf("results = %+v", results)
	}
	done := sh.resealStatus(sess.ID, queued.ID)
	if done.Status != resealDone || done.Values != (resealValuesView{Total: 7, Resealed: 2, Current: 3, Failed: 1, Pending: 1}) ||
		len(done.ChangeIDs) != 1 || len(done.Failures) != 1 || done.Failures[0].Key != "bad" || done.Failures[0].Document != 0 ||
		done.Failures[0].Region != "use1" || done.Failures[0].Path != "" {
		t.Fatalf("done = %+v", done)
	}
	// the command keeps counts only
	cmd, _, _ = sh.store.Command(ctx, queued.Agent.ID, cmd.ID)
	if cmd.Result != `{"resealed":2,"current":3,"failed":1}` {
		t.Fatalf("result kept = %s", cmd.Result)
	}

	// one pending change, a reseal, for old-token in the two use1 documents
	got := decode[sessionResponse](t, sh.do("alice", http.MethodGet, "/api/v1/repos/example-org/apps/session", nil, false)).Session
	var reseal *changeView
	for i, c := range got.Changes {
		if c.Kind == store.ChangeReseal {
			reseal = &got.Changes[i]
		} else if c.Kind != store.ChangeSeal {
			t.Errorf("change kind = %q", c.Kind)
		}
	}
	if reseal == nil || reseal.ID != done.ChangeIDs[0] || reseal.Key != "old-token" || len(reseal.Targets) != 2 ||
		*reseal.Targets[0].Index != 0 || *reseal.Targets[1].Index != 1 || reseal.Fingerprint != sh.key.Fingerprint ||
		!slices.Equal(reseal.ResealedFrom, []string{f.old.Fingerprint}) {
		t.Fatalf("changes = %+v", got.Changes)
	}
	// each opens with the env key, to the value it had, under its label
	stored, _ := sh.store.Changes(ctx, sess.ID, true)
	for _, c := range stored {
		if !c.Resealed() {
			continue
		}
		for i, ct := range c.Ciphertexts {
			raw, _ := base64.StdEncoding.DecodeString(ct)
			label := ssv1alpha1.EncryptionLabel(c.Targets[i].Namespace, "reseal", ssv1alpha1.StrictScope)
			v, err := sscrypto.HybridDecrypt(rand.Reader, map[string]*rsa.PrivateKey{"": sh.keyPriv}, raw, label)
			if err != nil || string(v) != f.values[*c.Targets[i].Index] {
				t.Fatalf("document %d opens to %q, %v", *c.Targets[i].Index, v, err)
			}
		}
	}

	// the pull request writes the reseal into the two use1 documents only,
	// and says so apart from the sealed value
	if code := sh.openPullRequest(sess.ID); code != http.StatusCreated {
		t.Fatalf("pull request = %d", code)
	}
	pull, _ := sh.github.PullRequest("example-org", "apps", 1)
	if pull.Title != "Seal 1 value and reseal 2 values in "+resealPath+" for dev" {
		t.Fatalf("title = %q", pull.Title)
	}
	for _, want := range []string{"Resealed: 2 values moved off older keys onto the env key", "| `" + resealPath + "` | `old-token` | `dev-use1-blue-apps/reseal`, `dev-use1-green-apps/reseal` |", "does not rotate them"} {
		if !strings.Contains(pull.Body, want) {
			t.Errorf("body lacks %q:\n%s", want, pull.Body)
		}
	}
	if !strings.Contains(pull.Message, "Resealed onto the env key:\n"+resealPath+": old-token\n") {
		t.Errorf("message:\n%s", pull.Message)
	}
	before := encryptedData(t, pull.Files[0].Before)
	after := encryptedData(t, pull.Files[0].After)
	for i := range after {
		for key, v := range after[i] {
			changed := v != before[i][key]
			want := key == "old-token"
			if changed != want {
				t.Errorf("document %d %s changed = %v", i, key, changed)
			}
		}
	}
	for _, ct := range stored {
		for _, c := range ct.Ciphertexts {
			if strings.Contains(pull.Body+pull.Message+pull.Title, c[:40]) {
				t.Fatal("a ciphertext is in the pull request's text")
			}
		}
	}
	// recorded as a reseal pull request from a session
	prs, _ := sh.store.ResealPullRequests(ctx, true, "")
	if len(prs) != 1 || prs[0].Source != store.SourceSession || prs[0].Number != 1 || prs[0].Values != 2 || prs[0].Files != 1 ||
		prs[0].RequestedBy != "alice" || !slices.Equal(prs[0].FromKeys, []string{f.old.Fingerprint}) || prs[0].Repo != "example-org/apps" {
		t.Fatalf("reseal pull requests = %+v", prs)
	}
	for _, event := range []string{"event=reseal.requested", "event=reseal.pr_opened"} {
		if !strings.Contains(sh.logs.String(), event) {
			t.Errorf("%s was not logged", event)
		}
	}
	for _, v := range f.values {
		if strings.Contains(sh.logs.String(), v) {
			t.Fatal("a value was logged")
		}
	}
}

// latestCommand returns the ID of an agent's newest command.
func latestCommand(t *testing.T, sh *sealHarness, agentID string) string {
	t.Helper()
	cmds, err := sh.store.Commands(context.Background(), agentID)
	if err != nil || len(cmds) == 0 {
		t.Fatalf("commands of %s: %v", agentID, err)
	}
	return cmds[len(cmds)-1].ID
}

func TestResealFile_Refusals(t *testing.T) {
	f := newResealFixture(t)
	sh := f.sh
	sess := sh.openSession()

	// for admins only, with the CSRF token
	if rec := sh.reseal("bob", sess.ID, resealPath); rec.Code != http.StatusForbidden {
		t.Fatalf("bob = %d", rec.Code)
	}
	if rec := sh.do("alice", http.MethodPost, "/api/v1/repos/example-org/apps/session/"+sess.ID+"/reseals",
		map[string]string{"path": resealPath}, false); rec.Code != http.StatusForbidden {
		t.Fatalf("without csrf = %d", rec.Code)
	}
	for name, tc := range map[string]struct {
		path string
		code int
	}{
		"no path":                  {"", http.StatusBadRequest},
		"undiscovered":             {"deploy/billing/deployment.yaml", http.StatusNotFound},
		"no document for this env": {"deploy/reports/sealed-secret.yaml", http.StatusConflict},
	} {
		if rec := sh.reseal("alice", sess.ID, tc.path); rec.Code != tc.code {
			t.Errorf("%s = %d %s", name, rec.Code, rec.Body)
		}
	}
	if rec := sh.reseal("alice", "01J00000000000000000000XXX", resealPath); rec.Code != http.StatusNotFound {
		t.Errorf("another session = %d", rec.Code)
	}

	// a file whose values would not fit among the session's changes is
	// refused up front, saying how many it needs
	full := []string{}
	for i := range maxChangesPerSession - 1 {
		full = append(full, fmt.Sprintf("held-%d", i))
	}
	if err := sh.store.ReserveChanges(context.Background(), sess.ID, places(full), nil, maxChangesPerSession,
		sh.clock().Add(time.Hour), sh.clock()); err != nil {
		t.Fatal(err)
	}
	rec := sh.reseal("alice", sess.ID, resealPath)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "can make 3 changes, one for each key") {
		t.Fatalf("over the cap = %d %s", rec.Code, rec.Body)
	}

	// the status says whether the env can reseal
	status := decode[statusView](t, sh.do("bob", http.MethodGet, "/api/v1/status", nil, false))
	if !status.CanReseal || status.ResealBlocked != "" {
		t.Fatalf("status = %+v", status)
	}

	// no agent's controller seals with the env key: each prefers the older
	// key, as clusters made in the same second may prefer their own
	for id := range sh.agents {
		sh.checkIn(id, sh.key.Key, f.old.Key)
	}
	rec = sh.reseal("alice", sess.ID, resealPath)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "seals with the env key") {
		t.Fatalf("no controller seals with the env key = %d %s", rec.Code, rec.Body)
	}
	status = decode[statusView](t, sh.do("bob", http.MethodGet, "/api/v1/status", nil, false))
	if status.CanReseal || !strings.Contains(status.ResealBlocked, "seals with the env key") {
		t.Fatalf("status = %+v", status)
	}

	// no agent can reseal: the agents report no reseal capability
	sh.caps = []string{protocol.CapabilitySeal}
	for id := range sh.agents {
		sh.checkIn(id, f.old.Key, sh.key.Key)
	}
	rec = sh.reseal("alice", sess.ID, resealPath)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "no agent is available to reseal") {
		t.Fatalf("no resealer = %d %s", rec.Code, rec.Body)
	}
	status = decode[statusView](t, sh.do("bob", http.MethodGet, "/api/v1/status", nil, false))
	if status.CanReseal || !strings.Contains(status.ResealBlocked, "reseal capability") {
		t.Fatalf("status = %+v", status)
	}
}

func places(ids []string) map[string]string {
	out := map[string]string{}
	for _, id := range ids {
		out[id] = "seal-" + id
	}
	return out
}

// A result the agent made up is refused: a resealed value must be the same
// value, with only its RSA part new.
func TestResealFile_RefusesAnotherValue(t *testing.T) {
	f := newResealFixture(t)
	sh := f.sh
	sess := sh.openSession()
	rec := sh.reseal("alice", sess.ID, resealPath)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("reseal = %d %s", rec.Code, rec.Body)
	}
	queued := decode[fileResealView](t, rec)
	poll := sh.agentDo(http.MethodGet, "/agent/v1/commands?wait=0", queued.Agent.ID, nil)
	cmds := decode[protocol.CommandsResponse](t, poll).Commands
	if len(cmds) != 1 {
		t.Fatalf("commands = %+v", cmds)
	}
	var p protocol.ResealPayload
	if err := json.Unmarshal(cmds[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	var res protocol.ResealResult
	for _, it := range p.Items {
		// another value, sealed with the env key under the same label
		res.Items = append(res.Items, protocol.ResealedItem{ID: it.ID, Status: protocol.ResealResealed, From: f.old.Fingerprint,
			Ciphertext: sealFor(t, sh.keyPriv, it.Namespace, it.Name, "attacker")})
	}
	body, _ := json.Marshal(res)
	out := sh.agentDo(http.MethodPost, "/agent/v1/commands/"+cmds[0].ID+"/result", queued.Agent.ID,
		protocol.CommandResult{Status: protocol.CommandSucceeded, Result: body})
	if out.Code != http.StatusBadRequest || !strings.Contains(out.Body.String(), "not the same value") {
		t.Fatalf("result = %d %s", out.Code, out.Body)
	}
	if changes, _ := sh.store.Changes(context.Background(), sess.ID, false); len(changes) != 0 {
		t.Fatalf("changes = %+v", changes)
	}
	if got := sh.resealStatus(sess.ID, queued.ID); got.Status != resealFailed || got.Values.Failed != 7 {
		t.Fatalf("status = %+v", got)
	}
}

// A command no agent answers expires, and its values count as failed.
func TestResealFile_Expires(t *testing.T) {
	f := newResealFixture(t)
	sh := f.sh
	sess := sh.openSession()
	rec := sh.reseal("alice", sess.ID, resealPath)
	queued := decode[fileResealView](t, rec)
	sh.advance(resealCommandTTL + time.Second)
	got := sh.resealStatus(sess.ID, queued.ID)
	if got.Status != resealExpired || got.Values.Failed != 7 || got.Values.Pending != 0 || len(got.Failures) != 7 ||
		got.Failures[1].Error != errNoAgentAnswered {
		t.Fatalf("status = %+v", got)
	}
}

// A file is not resealed while a seal of the session runs: the seal has no
// change yet to leave out.
func TestResealFile_RefusedWhileASealRuns(t *testing.T) {
	f := newResealFixture(t)
	sh := f.sh
	sess := sh.openSession()
	rec := sh.seal(sess.ID, resealPath, "old-token", "rotated")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("seal = %d %s", rec.Code, rec.Body)
	}
	seal := decode[sealView](t, rec)
	rec = sh.reseal("alice", sess.ID, resealPath)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "A seal is still running") {
		t.Fatalf("reseal while a seal runs = %d %s", rec.Code, rec.Body)
	}
	sh.runAgent(seal.Agent.ID)
	rec = sh.reseal("alice", sess.ID, resealPath)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("reseal after the seal = %d %s", rec.Code, rec.Body)
	}
	// the sealed key is left out in every document
	if got := decode[fileResealView](t, rec); got.Values.Pending != 3 {
		t.Fatalf("reseal = %+v", got)
	}
}

// In the pull request, a value sealed in the session wins over a reseal of
// the same key and document, even a newer one.
func TestResealFile_SealWinsInThePullRequest(t *testing.T) {
	f := newResealFixture(t)
	sh := f.sh
	ctx := context.Background()
	sess := sh.openSession()
	var docs []store.Target
	for i, ns := range []string{"dev-use1-blue-apps", "dev-use1-green-apps", "dev-use2-blue-apps"} {
		docs = append(docs, store.Target{Index: &i, Namespace: ns, Name: "reseal", Scope: "strict"})
	}
	base := store.Change{SessionID: sess.ID, Path: resealPath, Key: "old-token", AgentID: "dev-use1-blue",
		Fingerprint: sh.key.Fingerprint, UserID: 1001, UserLogin: "alice", SealedAt: sh.clock(), ExpiresAt: sess.EndsAt}
	// sealed for every document, then resealed in the first by a newer
	// command
	seal := base
	seal.ID, seal.CommandID, seal.Targets = changeID(resealPath, "old-token", nil), "01J0000000000000000000000A", docs
	seal.Ciphertexts = []string{"AgSEALED", "AgSEALED", "AgSEALED"}
	reseal := base
	reseal.ID, reseal.CommandID, reseal.Targets = resealChangeID(resealPath, "old-token", "x"), "01J0000000000000000000000B", docs[:1]
	reseal.Ciphertexts = []string{"AgRESEALED"}
	reseal.Kind, reseal.ResealedFrom = store.ChangeReseal, []string{f.old.Fingerprint}
	for _, c := range []store.Change{reseal, seal} {
		if ok, err := sh.store.PutChange(ctx, c); err != nil || !ok {
			t.Fatal(ok, err)
		}
	}
	if code := sh.openPullRequest(sess.ID); code != http.StatusCreated {
		t.Fatalf("pull request = %d", code)
	}
	pull, _ := sh.github.PullRequest("example-org", "apps", 1)
	if got := encryptedData(t, pull.Files[0].After)[0]["old-token"]; got != "AgSEALED" {
		t.Fatalf("document 0 old-token = %q, want the sealed value", got)
	}
}
