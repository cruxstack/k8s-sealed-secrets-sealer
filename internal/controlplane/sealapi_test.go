package controlplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	ssv1alpha1 "github.com/bitnami/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	sscrypto "github.com/bitnami/sealed-secrets/pkg/crypto"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/agent"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/agentauth"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/envelope"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/githubapp"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/manifest"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/mockgithub"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/registry"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/repos"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/testutil/testcerts"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/userauth"
)

const billing = "deploy/billing/sealed-secret.yaml"

// sealHarness is the dev env of the local stack, with the GitHub mock's
// fixture repositories: three seal-only agents in two regions.
type sealHarness struct {
	t        *testing.T
	h        http.Handler
	store    *store.Memory
	kms      *envelope.FakeKMS
	logs     *bytes.Buffer
	agents   map[string]string // agent ID -> session token
	users    *userauth.Sessions
	key      testKey
	keyPriv  *rsa.PrivateKey
	sessions map[string]string // login -> session cookie
	github   *mockgithub.Server
	app      *githubapp.Client

	mu  sync.Mutex
	now time.Time
	// reload, when set, reads the registry again; nil leaves it unchanged
	reload func(context.Context) (*registry.Registry, map[string]LoginVerifier, error)
}

// newSealHarness serves the fixture repositories, with files added to
// example-org/apps (path to content) for one test.
func newSealHarness(t *testing.T, files ...map[string]string) *sealHarness {
	t.Helper()
	fixtures, err := mockgithub.Fixtures()
	if err != nil {
		t.Fatal(err)
	}
	for _, add := range files {
		for i, r := range fixtures {
			if r.Owner == "example-org" && r.Name == "apps" {
				fixtures[i].Files = maps.Clone(r.Files)
				maps.Copy(fixtures[i].Files, add)
			}
		}
	}
	appKey := testcerts.RSA(t, 2048)
	github := mockgithub.New(mockgithub.Options{
		Org:   "example-org",
		Users: mockgithub.DefaultUsers(),
		App:   mockgithub.App{ID: "1", PublicKey: &appKey.PublicKey, InstallationID: 1},
		Repos: fixtures,
	})
	mock := httptest.NewServer(github.Handler())
	t.Cleanup(mock.Close)
	gh, err := githubapp.New(githubapp.Options{
		APIURL: mock.URL, AppID: "1", Org: "example-org",
		PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(appKey)}),
	})
	if err != nil {
		t.Fatal(err)
	}
	rs, err := repos.New(repos.Options{
		GitHub: gh, Env: "dev",
		Annotations: manifest.Annotations{Env: manifest.DefaultEnvAnnotation, Region: manifest.DefaultRegionAnnotation},
	})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := registry.Parse([]byte(`
issuers: [{name: local, url: "https://k8s.example.com", jwksFile: k.json}]
agents:
  - {id: dev-use1-blue, cluster: dev-use1-blue, region: use1, capabilities: [seal], identity: {k8s: {issuer: local, subject: "system:serviceaccount:a:agent"}}}
  - {id: dev-use1-green, cluster: dev-use1-green, region: use1, capabilities: [seal], identity: {k8s: {issuer: local, subject: "system:serviceaccount:b:agent"}}}
  - {id: dev-use2-blue, cluster: dev-use2-blue, region: use2, capabilities: [seal], identity: {k8s: {issuer: local, subject: "system:serviceaccount:c:agent"}}}
`), "")
	if err != nil {
		t.Fatal(err)
	}
	agentSessions, _ := agentauth.NewSessions([]byte("0123456789abcdef0123456789abcdef"), "https://sealer.dev.example.com", "dev", nil)
	userSessions, _ := userauth.NewSessions([]byte("fedcba9876543210fedcba9876543210"), "https://sealer.dev.example.com", time.Hour, nil)
	users := userauth.NewHandler(userauth.HandlerOptions{
		Sessions: userSessions, PublicURL: "http://localhost:4100", Org: "example-org",
		Envs: []userauth.EnvPolicy{{Name: "dev"}}, Logger: slog.New(slog.DiscardHandler),
	})

	sh := &sealHarness{
		t: t, store: store.NewMemory(), kms: envelope.NewFakeKMS("transit"), logs: &bytes.Buffer{},
		agents: map[string]string{}, users: userSessions, sessions: map[string]string{}, github: github, app: gh,
		now: time.Now().UTC(), key: newTestKey(t, time.Now().Add(-time.Hour)),
	}
	block, _ := pem.Decode(sh.key.PrivatePEM)
	if sh.keyPriv, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		t.Fatal(err)
	}
	sh.h = New(Options{
		Logger:       slog.New(slog.NewTextHandler(sh.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Env:          "dev",
		Registry:     reg,
		Sessions:     agentSessions,
		Store:        sh.store,
		Users:        users.Env("dev"),
		Repos:        rs,
		Transit:      sh.kms,
		TransitKeyID: "transit",
		PollInterval: 10 * time.Millisecond,
		Now:          sh.clock,
		ReloadRegistry: func(ctx context.Context) (*registry.Registry, map[string]LoginVerifier, error) {
			sh.mu.Lock()
			reload := sh.reload
			sh.mu.Unlock()
			if reload == nil {
				return nil, nil, nil
			}
			return reload(ctx)
		},
	}).Handler()
	for _, a := range reg.Agents {
		sh.agents[a.ID] = agentSession(t, agentSessions, reg, a.ID)
		sh.checkIn(a.ID, sh.key.Key)
	}
	return sh
}

func (sh *sealHarness) clock() time.Time {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	return sh.now
}

func (sh *sealHarness) advance(d time.Duration) {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	sh.now = sh.now.Add(d)
}

// checkIn reports a seal-only agent holding keys.
func (sh *sealHarness) checkIn(id string, keys ...protocol.Key) {
	sh.t.Helper()
	in := checkIn(keys...)
	in.Capabilities = []string{protocol.CapabilitySeal}
	in.Commands = []string{protocol.CommandSeal}
	rec := sh.agentDo(http.MethodPost, "/agent/v1/checkin", id, in)
	if rec.Code != http.StatusOK {
		sh.t.Fatalf("check-in %s = %d %s", id, rec.Code, rec.Body)
	}
}

func (sh *sealHarness) agentDo(method, path, id string, body any) *httptest.ResponseRecorder {
	sh.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			sh.t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sh.agents[id])
	rec := httptest.NewRecorder()
	sh.h.ServeHTTP(rec, req)
	return rec
}

var testUsers = map[string]userauth.User{
	"alice": {ID: 1001, Login: "alice"},
	"bob":   {ID: 1002, Login: "bob"},
}

// do sends a request as a signed-in user, with the CSRF token unless
// csrf is false.
func (sh *sealHarness) do(login, method, path string, body any, csrf bool) *httptest.ResponseRecorder {
	sh.t.Helper()
	token, ok := sh.sessions[login]
	if !ok {
		var err error
		if token, _, err = sh.users.Issue(testUsers[login], userauth.Grants{"dev": false}); err != nil {
			sh.t.Fatal(err)
		}
		sh.sessions[login] = token
	}
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			sh.t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "sealer_session", Value: token})
	if csrf {
		req.Header.Set(userauth.CSRFHeader, sh.users.CSRFToken(token))
	}
	rec := httptest.NewRecorder()
	sh.h.ServeHTTP(rec, req)
	return rec
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.NewDecoder(bytes.NewReader(rec.Body.Bytes())).Decode(&v); err != nil {
		t.Fatalf("decode %s: %v", rec.Body, err)
	}
	return v
}

type sessionResponse struct {
	Session *sessionView `json:"session"`
}

// openSession opens alice's session on example-org/apps.
func (sh *sealHarness) openSession() sessionView {
	sh.t.Helper()
	rec := sh.do("alice", http.MethodPost, "/api/v1/repos/example-org/apps/session", map[string]string{}, true)
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		sh.t.Fatalf("open session = %d %s", rec.Code, rec.Body)
	}
	return *decode[sessionResponse](sh.t, rec).Session
}

func (sh *sealHarness) seal(sessionID, path, key, value string) *httptest.ResponseRecorder {
	sh.t.Helper()
	return sh.do("alice", http.MethodPost, "/api/v1/repos/example-org/apps/session/"+sessionID+"/seals",
		map[string]string{"path": path, "key": key, "value": value}, true)
}

func (sh *sealHarness) sealStatus(sessionID, id string) sealView {
	sh.t.Helper()
	rec := sh.do("alice", http.MethodGet, "/api/v1/repos/example-org/apps/session/"+sessionID+"/seals/"+id, nil, false)
	if rec.Code != http.StatusOK {
		sh.t.Fatalf("seal status = %d %s", rec.Code, rec.Body)
	}
	return decode[sealView](sh.t, rec)
}

// runAgent leases the agent's commands and runs them with the real seal
// handler, as the agent would, reporting each result.
func (sh *sealHarness) runAgent(id string) []protocol.CommandResult {
	sh.t.Helper()
	rec := sh.agentDo(http.MethodGet, "/agent/v1/commands?wait=0", id, nil)
	if rec.Code != http.StatusOK {
		sh.t.Fatalf("poll %s = %d %s", id, rec.Code, rec.Body)
	}
	sealer := agent.NewSealer(agent.SealerOptions{
		Keys:         staticKeys{sh.key.Key},
		KMS:          sh.kms,
		TransitKeyID: "transit",
		Env:          "dev",
		AgentID:      func() string { return id },
		Logger:       slog.New(slog.DiscardHandler),
	})
	var results []protocol.CommandResult
	for _, cmd := range decode[protocol.CommandsResponse](sh.t, rec).Commands {
		res := protocol.CommandResult{Status: protocol.CommandSucceeded}
		out, err := sealer.Seal(context.Background(), cmd)
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

type staticKeys []protocol.Key

func (k staticKeys) Collect(context.Context) (agent.Report, error) {
	return agent.Report{Keys: k, Complete: true}, nil
}

func TestSealFlow(t *testing.T) {
	sh := newSealHarness(t)
	base := "/api/v1/repos/example-org/apps/session"

	// no session yet
	rec := sh.do("alice", http.MethodGet, base, nil, false)
	if rec.Code != http.StatusOK || decode[sessionResponse](t, rec).Session != nil {
		t.Fatalf("no session = %d %s", rec.Code, rec.Body)
	}
	// opening one needs the CSRF token, write access and the current head
	if rec := sh.do("alice", http.MethodPost, base, map[string]string{}, false); rec.Code != http.StatusForbidden {
		t.Fatalf("open without csrf = %d", rec.Code)
	}
	if rec := sh.do("bob", http.MethodPost, base, map[string]string{}, true); rec.Code != http.StatusForbidden {
		t.Fatalf("bob (read only) opened a session: %d", rec.Code)
	}
	if rec := sh.do("alice", http.MethodPost, base, map[string]string{"commit": strings.Repeat("a", 40)}, true); rec.Code != http.StatusConflict {
		t.Fatalf("open at a stale commit = %d %s", rec.Code, rec.Body)
	}
	sess := sh.openSession()
	if !githubapp.ValidSHA(sess.Commit) || sess.Branch != "main" || sess.Repository != "example-org/apps" || len(sess.Changes) != 0 {
		t.Fatalf("session = %+v", sess)
	}
	if again := sh.openSession(); again.ID != sess.ID {
		t.Fatalf("a second open made another session: %s", again.ID)
	}

	// seal into the billing file: one value for its three dev documents
	rec = sh.seal(sess.ID, billing, "api-token", "s3cr3t-value")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("seal = %d %s", rec.Code, rec.Body)
	}
	seal := decode[sealView](t, rec)
	if seal.Status != sealQueued || len(seal.Targets) != 3 || seal.Fingerprint != sh.key.Fingerprint || seal.Agent.Cluster == "" {
		t.Fatalf("seal = %+v", seal)
	}
	// the value is stored only as transit ciphertext, apart from the payload
	cmd, ok, _ := sh.store.Command(context.Background(), seal.Agent.ID, seal.ID)
	if !ok || cmd.Secret == "" || strings.Contains(cmd.Payload, "value") || strings.Contains(cmd.Secret, "s3cr3t") {
		t.Fatalf("command = %+v", cmd)
	}
	if got := sh.sealStatus(sess.ID, seal.ID); got.Status != sealQueued {
		t.Fatalf("status = %+v", got)
	}

	// the chosen agent seals; no other agent is sent the command
	for id := range sh.agents {
		if id != seal.Agent.ID {
			if res := sh.runAgent(id); len(res) != 0 {
				t.Fatalf("%s ran %+v", id, res)
			}
		}
	}
	res := sh.runAgent(seal.Agent.ID)
	if len(res) != 1 || res[0].Status != protocol.CommandSucceeded {
		t.Fatalf("agent results = %+v", res)
	}
	// the finished command keeps only a summary: the fingerprint and how
	// many targets, never the ciphertexts
	cmd, _, _ = sh.store.Command(context.Background(), seal.Agent.ID, seal.ID)
	var summary map[string]json.RawMessage
	if cmd.Secret != "" || json.Unmarshal([]byte(cmd.Result), &summary) != nil || len(summary) != 2 ||
		string(summary["fingerprint"]) != strconv.Quote(sh.key.Fingerprint) || string(summary["targets"]) != "3" {
		t.Fatalf("finished command keeps the secret or more than a summary: %+v", cmd)
	}
	done := sh.sealStatus(sess.ID, seal.ID)
	if done.Status != sealSealed || done.ChangeID == "" {
		t.Fatalf("status = %+v", done)
	}

	// the session shows the change, never its ciphertexts
	rec = sh.do("alice", http.MethodGet, base, nil, false)
	got := decode[sessionResponse](t, rec).Session
	if got == nil || len(got.Changes) != 1 {
		t.Fatalf("session = %s", rec.Body)
	}
	change := got.Changes[0]
	if change.ID != done.ChangeID || change.Path != billing || change.Key != "api-token" || len(change.Targets) != 3 ||
		change.SealedBy.ID != seal.Agent.ID || change.Fingerprint != sh.key.Fingerprint {
		t.Fatalf("change = %+v", change)
	}
	stored, _ := sh.store.Changes(context.Background(), sess.ID, true)
	for i, ct := range stored[0].Ciphertexts {
		if strings.Contains(rec.Body.String(), ct[:40]) {
			t.Fatal("the session response holds a ciphertext")
		}
		target := stored[0].Targets[i]
		raw, _ := base64.StdEncoding.DecodeString(ct)
		label := ssv1alpha1.EncryptionLabel(target.Namespace, target.Name, ssv1alpha1.StrictScope)
		plain, err := sscrypto.HybridDecrypt(rand.Reader, map[string]*rsa.PrivateKey{"": sh.keyPriv}, raw, label)
		if err != nil || string(plain) != "s3cr3t-value" {
			t.Fatalf("target %s/%s decrypts to %q, %v", target.Namespace, target.Name, plain, err)
		}
	}
	if strings.Contains(sh.logs.String(), "s3cr3t") {
		t.Fatal("the value was logged")
	}
	for _, event := range []string{"event=session.opened", "event=seal.requested", "event=seal.succeeded"} {
		if !strings.Contains(sh.logs.String(), event) {
			t.Errorf("%s was not logged", event)
		}
	}

	// the user's sessions, with their pending changes counted
	rec = sh.do("alice", http.MethodGet, "/api/v1/sessions", nil, false)
	list := decode[struct {
		Sessions []sessionView `json:"sessions"`
	}](t, rec).Sessions
	if len(list) != 1 || list[0].ID != sess.ID || list[0].PendingChanges != 1 || list[0].Changes != nil {
		t.Fatalf("sessions = %s", rec.Body)
	}
	if rec := sh.do("bob", http.MethodGet, "/api/v1/sessions", nil, false); !strings.Contains(rec.Body.String(), `"sessions":[]`) {
		t.Fatalf("bob's sessions = %s", rec.Body)
	}

	// sealing the same key again replaces the change
	rec = sh.seal(sess.ID, billing, "api-token", "rotated")
	sh.runAgent(decode[sealView](t, rec).Agent.ID)
	if list, _ := sh.store.Changes(context.Background(), sess.ID, false); len(list) != 1 || list[0].CommandID == seal.ID {
		t.Fatalf("changes after resealing = %+v", list)
	}

	// another user cannot see or use alice's session
	if rec := sh.do("bob", http.MethodGet, base+"/"+sess.ID+"/seals/"+seal.ID, nil, false); rec.Code != http.StatusNotFound {
		t.Fatalf("bob read alice's seal: %d", rec.Code)
	}

	// removing the change, then discarding the session
	if rec := sh.do("alice", http.MethodDelete, base+"/"+sess.ID+"/changes/"+change.ID, nil, true); rec.Code != http.StatusNoContent {
		t.Fatalf("remove change = %d %s", rec.Code, rec.Body)
	}
	if rec := sh.do("alice", http.MethodDelete, base+"/"+sess.ID+"/changes/"+change.ID, nil, true); rec.Code != http.StatusNotFound {
		t.Fatalf("remove change again = %d", rec.Code)
	}
	if rec := sh.do("alice", http.MethodDelete, base+"/"+sess.ID, nil, false); rec.Code != http.StatusForbidden {
		t.Fatalf("discard without csrf = %d", rec.Code)
	}
	if rec := sh.do("alice", http.MethodDelete, base+"/"+sess.ID, nil, true); rec.Code != http.StatusNoContent {
		t.Fatalf("discard = %d %s", rec.Code, rec.Body)
	}
	if rec := sh.seal(sess.ID, billing, "api-token", "v"); rec.Code != http.StatusNotFound {
		t.Fatalf("seal into a discarded session = %d", rec.Code)
	}
}

func TestSeal_Refuses(t *testing.T) {
	sh := newSealHarness(t)
	sess := sh.openSession()
	cases := map[string]struct {
		path, key, value string
		want             int
		msg              string
	}{
		"cluster-wide document": {"deploy/legacy/sealed-secret.yaml", "k", "v", http.StatusUnprocessableEntity, "cluster-wide"},
		"prod-only file":        {"deploy/reports/sealed-secret.yaml", "k", "v", http.StatusUnprocessableEntity, "no SealedSecret for the dev env"},
		"undiscovered file":     {"deploy/billing/deployment.yaml", "k", "v", http.StatusNotFound, "no SealedSecret file"},
		"invalid key":           {billing, "a/b", "v", http.StatusBadRequest, "valid Secret key"},
		"empty value":           {billing, "k", "", http.StatusBadRequest, "value is required"},
		"value too large":       {billing, "k", strings.Repeat("x", protocol.MaxSealValueBytes+1), http.StatusRequestEntityTooLarge, "larger than"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rec := sh.seal(sess.ID, tc.path, tc.key, tc.value)
			if rec.Code != tc.want || !strings.Contains(rec.Body.String(), tc.msg) {
				t.Fatalf("= %d %s, want %d %q", rec.Code, rec.Body, tc.want, tc.msg)
			}
		})
	}
	if rec := sh.seal("01J0000000000000000000000Z", billing, "k", "v"); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown session = %d", rec.Code)
	}

	// keys out of sync: one cluster has only a key the others lack
	other := protoKey(t, time.Now())
	sh.checkIn("dev-use2-blue", other)
	rec := sh.seal(sess.ID, billing, "k", "v")
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "keys out of sync") {
		t.Fatalf("out of sync = %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(sh.logs.String(), "event=keys.out_of_sync") {
		t.Error("a seal refused for keys out of sync was not logged")
	}
	sh.checkIn("dev-use2-blue", sh.key.Key, other)

	// no healthy agent
	sh.advance(time.Minute)
	if rec := sh.seal(sess.ID, billing, "k", "v"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no agent = %d %s", rec.Code, rec.Body)
	}
}

func TestSeal_ResultsAndExpiry(t *testing.T) {
	sh := newSealHarness(t)
	sess := sh.openSession()

	rec := sh.seal(sess.ID, billing, "k", "v")
	seal := decode[sealView](t, rec)

	// a result that does not match the command fails the seal
	poll := sh.agentDo(http.MethodGet, "/agent/v1/commands?wait=0", seal.Agent.ID, nil)
	cmds := decode[protocol.CommandsResponse](t, poll).Commands
	if len(cmds) != 1 {
		t.Fatalf("commands = %+v", cmds)
	}
	bad, _ := json.Marshal(protocol.SealResult{Fingerprint: sh.key.Fingerprint, Targets: []protocol.SealedTarget{{Namespace: "x", Name: "y", Ciphertext: "QQ=="}}})
	res := sh.agentDo(http.MethodPost, "/agent/v1/commands/"+cmds[0].ID+"/result", seal.Agent.ID,
		protocol.CommandResult{Status: protocol.CommandSucceeded, Result: bad})
	if res.Code != http.StatusBadRequest {
		t.Fatalf("bad result = %d %s", res.Code, res.Body)
	}
	if got := sh.sealStatus(sess.ID, seal.ID); got.Status != sealFailed || !strings.Contains(got.Error, "invalid result") {
		t.Fatalf("status = %+v", got)
	}
	if list, _ := sh.store.Changes(context.Background(), sess.ID, false); len(list) != 0 {
		t.Fatalf("a bad result became a change: %+v", list)
	}

	// an agent's own failure is shown as it reported it
	seal = decode[sealView](t, sh.seal(sess.ID, billing, "k", "v"))
	sh.agentDo(http.MethodGet, "/agent/v1/commands?wait=0", seal.Agent.ID, nil)
	sh.agentDo(http.MethodPost, "/agent/v1/commands/"+seal.ID+"/result", seal.Agent.ID,
		protocol.CommandResult{Status: protocol.CommandFailed, Error: "refusing to seal: key is not in this cluster's key set"})
	if got := sh.sealStatus(sess.ID, seal.ID); got.Status != sealFailed || !strings.Contains(got.Error, "key set") {
		t.Fatalf("status = %+v", got)
	}

	// a seal that does not finish in time expires, and a late result is
	// refused
	seal = decode[sealView](t, sh.seal(sess.ID, billing, "k", "v"))
	sh.agentDo(http.MethodGet, "/agent/v1/commands?wait=0", seal.Agent.ID, nil)
	if got := sh.sealStatus(sess.ID, seal.ID); got.Status != sealSealing {
		t.Fatalf("status = %+v", got)
	}
	sh.advance(sealCommandTTL)
	if got := sh.sealStatus(sess.ID, seal.ID); got.Status != sealExpired {
		t.Fatalf("status = %+v", got)
	}
	late, _ := json.Marshal(protocol.SealResult{Fingerprint: sh.key.Fingerprint})
	if rec := sh.agentDo(http.MethodPost, "/agent/v1/commands/"+seal.ID+"/result", seal.Agent.ID,
		protocol.CommandResult{Status: protocol.CommandSucceeded, Result: late}); rec.Code != http.StatusConflict {
		t.Fatalf("late result = %d %s", rec.Code, rec.Body)
	}
}

func TestViewSession_SortsChangesByFileKeyAndRegions(t *testing.T) {
	use1 := []store.Target{{Namespace: "use1", Name: "x", Region: "use1"}}
	use2 := []store.Target{{Namespace: "use2", Name: "x", Region: "use2"}}
	both := append(slices.Clone(use1), use2...)
	changes := []store.Change{
		{ID: "1", Path: "b.yaml", Key: "a", CommandID: "01A", Targets: both},
		{ID: "2", Path: "a.yaml", Key: "z", CommandID: "01B", Regions: []string{"use2"}, Targets: use2},
		{ID: "3", Path: "a.yaml", Key: "b", CommandID: "01C", Targets: both},
		{ID: "4", Path: "a.yaml", Key: "z", CommandID: "01D", Targets: both},
		{ID: "5", Path: "a.yaml", Key: "b", CommandID: "01E", Regions: []string{"use1"}, Targets: use1},
	}
	v := viewSession(store.Session{}, changes, nil, func(id string) agentView { return agentView{ID: id} })
	var got []string
	for _, c := range v.Changes {
		got = append(got, fmt.Sprintf("%s:%s%v:%d", c.Path, c.Key, c.Regions, len(c.Targets)))
	}
	// z for use2 was sealed before z for both, which covers it; b for use1
	// was sealed after b for both, which keeps use2
	want := "a.yaml:b[]:1,a.yaml:b[use1]:1,a.yaml:z[]:2,b.yaml:a[]:2"
	if strings.Join(got, ",") != want || v.PendingChanges != 4 || changes[0].ID != "1" {
		t.Fatalf("changes = %v (%d)", got, v.PendingChanges)
	}
}

func TestSealRegions(t *testing.T) {
	docs := []manifest.Document{{Region: "use1"}, {Region: "use2"}, {Region: ""}}
	cases := map[string]struct {
		named []string
		want  []string
		err   string
	}{
		"none":            {nil, nil, ""},
		"one":             {[]string{"use2"}, []string{"use2"}, ""},
		"sorted, once":    {[]string{"use2", "use1", "use2"}, []string{"use1", "use2"}, ""},
		"not in the file": {[]string{"use3"}, nil, `no document of this file for the env is in region "use3"`},
		"empty":           {[]string{""}, nil, "region names"},
		"upper case":      {[]string{"USE1"}, nil, "region names"},
		"new lines":       {[]string{"use1)\n\nCo-authored-by: x <x@example.com>"}, nil, "region names"},
		"too long":        {[]string{strings.Repeat("a", 64)}, nil, "region names"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := sealRegions(tc.named, docs)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("sealRegions = %v, %v; want error %q", got, err, tc.err)
				}
				return
			}
			if err != nil || !slices.Equal(got, tc.want) {
				t.Fatalf("sealRegions = %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}
