package controlplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/agentauth"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/envelope"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/fleet"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/keys"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/registry"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/testutil/testcerts"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/userauth"
)

// faultyStore fails reads of every agent's state while failStateReads is
// set, and counts reads of an agent's commands.
type faultyStore struct {
	store.Store
	failStateReads atomic.Bool
	commandReads   atomic.Int32
}

func (f *faultyStore) CommandsSince(ctx context.Context, agentID string, since time.Time) ([]store.CommandRecord, error) {
	f.commandReads.Add(1)
	return f.Store.CommandsSince(ctx, agentID, since)
}

func (f *faultyStore) GetAgentStates(ctx context.Context, ids []string) (map[string]store.AgentState, error) {
	if f.failStateReads.Load() {
		return nil, errors.New("throttled")
	}
	return f.Store.GetAgentStates(ctx, ids)
}

// keyHarness is the sync harness's env (a: seal, keys, renewal; b: seal,
// keys; c: seal) with the admin API, and alice, an admin of dev, and bob,
// who is not, signed in.
type keyHarness struct {
	*syncHarness
	faulty *faultyStore
	users  *userauth.Sessions
}

func newKeyHarness(t *testing.T) *keyHarness {
	t.Helper()
	reg, err := registry.Parse([]byte(`
issuers: [{name: local, url: "https://k8s.example.com", jwksFile: k.json}]
agents:
  - {id: a, cluster: a, region: use1, capabilities: [seal, keys, renewal], identity: {k8s: {issuer: local, subject: "system:serviceaccount:a:agent"}}}
  - {id: b, cluster: b, region: use1, capabilities: [seal, keys], identity: {k8s: {issuer: local, subject: "system:serviceaccount:b:agent"}}}
  - {id: c, cluster: c, region: use2, capabilities: [seal], identity: {k8s: {issuer: local, subject: "system:serviceaccount:c:agent"}}}
`), "")
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := agentauth.NewSessions([]byte("0123456789abcdef0123456789abcdef"), "https://sealer.dev.example.com", "dev", nil)
	if err != nil {
		t.Fatal(err)
	}
	userSessions, err := userauth.NewSessions([]byte("fedcba9876543210fedcba9876543210"), "https://sealer.dev.example.com", time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	users := userauth.NewHandler(userauth.HandlerOptions{
		Sessions: userSessions, PublicURL: "http://localhost:4100", Org: "example-org",
		Envs: []userauth.EnvPolicy{{Name: "dev"}}, Logger: slog.New(slog.DiscardHandler),
	})
	logs := &bytes.Buffer{}
	mem := store.NewMemory()
	faulty := &faultyStore{Store: mem}
	sh := &syncHarness{sessions: map[string]string{}, kms: envelope.NewFakeKMS("escrow"), now: time.Now().UTC()}
	sh.srv = New(Options{
		Logger:       slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Env:          "dev",
		Registry:     reg,
		Sessions:     sessions,
		Store:        faulty,
		AdminToken:   adminToken,
		Users:        users.Env("dev"),
		PollInterval: 10 * time.Millisecond,
		Now:          sh.clock,

		AdminTokenKeyChanges: true,
	})
	sh.harness = &harness{t: t, h: sh.srv.Handler(), store: mem, logs: logs}
	for _, id := range []string{"a", "b", "c"} {
		sh.sessions[id] = agentSession(t, sessions, reg, id)
	}
	return &keyHarness{syncHarness: sh, faulty: faulty, users: userSessions}
}

// userDo sends a request as alice (an admin of dev) or bob, with the CSRF
// token unless csrf is false.
func (kh *keyHarness) userDo(login, method, path string, csrf bool) *httptest.ResponseRecorder {
	kh.t.Helper()
	token, _, err := kh.users.Issue(userauth.User{ID: int64(len(login)), Login: login}, userauth.Grants{"dev": login == "alice"})
	if err != nil {
		kh.t.Fatal(err)
	}
	req := httptest.NewRequest(method, path, nil)
	req.AddCookie(&http.Cookie{Name: "sealer_session", Value: token})
	if csrf {
		req.Header.Set(userauth.CSRFHeader, kh.users.CSRFToken(token))
	}
	rec := httptest.NewRecorder()
	kh.h.ServeHTTP(rec, req)
	return rec
}

func (kh *keyHarness) fleet() fleet.Fleet {
	kh.t.Helper()
	rec := kh.do(http.MethodGet, "/api/v1/admin/fleet", adminToken, nil)
	if rec.Code != http.StatusOK {
		kh.t.Fatalf("fleet = %d %s", rec.Code, rec.Body)
	}
	return decode[fleet.Fleet](kh.t, rec)
}

func (kh *keyHarness) setStatus(fp, action string) *httptest.ResponseRecorder {
	kh.t.Helper()
	return kh.do(http.MethodPost, "/api/v1/admin/keys/"+protocol.FingerprintPath(fp)+"/"+action, adminToken, nil)
}

func (kh *keyHarness) download(id, fp string) *httptest.ResponseRecorder {
	kh.t.Helper()
	return kh.do(http.MethodGet, "/agent/v1/escrow/"+protocol.FingerprintPath(fp), kh.sessions[id], nil)
}

func fleetKey(t *testing.T, f fleet.Fleet, fp string) fleet.Key {
	t.Helper()
	for _, k := range f.Keys {
		if k.Fingerprint == fp {
			return k
		}
	}
	t.Fatalf("key %s not in the fleet", fp)
	return fleet.Key{}
}

func fleetAgent(t *testing.T, f fleet.Fleet, id string) fleet.Agent {
	t.Helper()
	for _, a := range f.Agents {
		if a.ID == id {
			return a
		}
	}
	t.Fatalf("agent %s not in the fleet", id)
	return fleet.Agent{}
}

func TestKeyStatus_RevokeAndReinstate(t *testing.T) {
	kh := newKeyHarness(t)
	ka := newTestKey(t, time.Now().Add(-2*time.Hour))
	kb := newTestKey(t, time.Now().Add(-time.Hour))
	kh.checkIn("a", "720h0m0s", ka, kb)
	kh.checkIn("b", "0s", ka, kb)
	if f := kh.fleet(); f.EnvKey == nil || f.EnvKey.Fingerprint != kb.Fingerprint {
		t.Fatalf("env key = %+v, want kb", f.EnvKey)
	}

	path := "/api/v1/keys/" + protocol.FingerprintPath(kb.Fingerprint) + "/revoke"
	if rec := kh.userDo("bob", http.MethodPost, path, true); rec.Code != http.StatusForbidden {
		t.Fatalf("revoke by a user who is not an admin = %d", rec.Code)
	}
	if rec := kh.userDo("alice", http.MethodPost, path, false); rec.Code != http.StatusForbidden {
		t.Fatalf("revoke without the CSRF token = %d", rec.Code)
	}
	unknown := protoKey(t, time.Now())
	if rec := kh.userDo("alice", http.MethodPost, "/api/v1/keys/"+protocol.FingerprintPath(unknown.Fingerprint)+"/revoke", true); rec.Code != http.StatusNotFound {
		t.Fatalf("revoke of an unknown key = %d", rec.Code)
	}
	if rec := kh.userDo("alice", http.MethodPost, "/api/v1/keys/nope/revoke", true); rec.Code != http.StatusNotFound {
		t.Fatalf("revoke of a malformed fingerprint = %d", rec.Code)
	}

	rec := kh.userDo("alice", http.MethodPost, path, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d %s", rec.Code, rec.Body)
	}
	if v := decode[keyStatusView](t, rec); v.Status != store.KeyRevoked || v.StatusBy != "alice" || v.StatusAt == nil {
		t.Fatalf("revoked = %+v", v)
	}
	f := kh.fleet()
	if f.EnvKey == nil || f.EnvKey.Fingerprint != ka.Fingerprint {
		t.Fatalf("env key after revoking kb = %+v, want ka", f.EnvKey)
	}
	if k := fleetKey(t, f, kb.Fingerprint); k.Status != store.KeyRevoked || k.RevokedBy != "alice" || len(k.Holders) != 2 {
		t.Fatalf("revoked key in the fleet = %+v", k)
	}
	// revoking again changes nothing
	if rec := kh.userDo("alice", http.MethodPost, path, true); rec.Code != http.StatusOK {
		t.Fatalf("revoke again = %d", rec.Code)
	}
	if n := strings.Count(kh.logs.String(), "event=key.revoked"); n != 1 {
		t.Fatalf("key.revoked logged %d times, want 1", n)
	}
	if !strings.Contains(kh.logs.String(), "user=alice") {
		t.Error("key.revoked does not name the user")
	}

	// the web UI escapes the fingerprint's colon (encodeURIComponent)
	escaped := "/api/v1/keys/" + strings.Replace(protocol.FingerprintPath(kb.Fingerprint), ":", "%3A", 1) + "/revoke"
	if rec := kh.userDo("alice", http.MethodPost, escaped, true); rec.Code != http.StatusOK || !strings.Contains(escaped, "%3A") {
		t.Fatalf("revoke at %s = %d", escaped, rec.Code)
	}

	// the admin token reinstates it, for scripts
	rec = kh.setStatus(kb.Fingerprint, "reinstate")
	if v := decode[keyStatusView](t, rec); rec.Code != http.StatusOK || v.Status != store.KeyActive || v.StatusBy != adminTokenActor {
		t.Fatalf("reinstate = %d %+v", rec.Code, v)
	}
	if f := kh.fleet(); f.EnvKey == nil || f.EnvKey.Fingerprint != kb.Fingerprint || fleetKey(t, f, kb.Fingerprint).Status != store.KeyActive {
		t.Fatalf("env key after reinstating kb = %+v", f.EnvKey)
	}
	if !strings.Contains(kh.logs.String(), "event=key.reinstated") {
		t.Error("key.reinstated was not logged")
	}
	if rec := kh.do(http.MethodPost, "/api/v1/admin/keys/"+protocol.FingerprintPath(kb.Fingerprint)+"/revoke", "wrong", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoke with a wrong admin token = %d", rec.Code)
	}
}

// The admin token reads the fleet, and changes keys only where the env
// allows it: it is often shared, and given to monitoring.
func TestKeyStatus_AdminTokenChangesKeysOnlyWhenAllowed(t *testing.T) {
	h := newHarness(t, adminToken)
	k := protoKey(t, time.Now().Add(-time.Hour))
	if rec := h.do(http.MethodPost, "/agent/v1/checkin", h.login(), checkIn(k)); rec.Code != http.StatusOK {
		t.Fatalf("check-in = %d %s", rec.Code, rec.Body)
	}
	for _, action := range []string{"revoke", "reinstate"} {
		path := "/api/v1/admin/keys/" + protocol.FingerprintPath(k.Fingerprint) + "/" + action
		if rec := h.do(http.MethodPost, path, "wrong", nil); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s with a wrong token = %d", action, rec.Code)
		}
		if rec := h.do(http.MethodPost, path, adminToken, nil); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "adminTokenKeyChanges") {
			t.Fatalf("%s with the admin token = %d %s", action, rec.Code, rec.Body)
		}
	}
	if rec, _, _ := h.store.GetKey(context.Background(), k.Fingerprint); rec.Status == store.KeyRevoked {
		t.Fatal("the admin token revoked a key")
	}
	if rec := h.do(http.MethodGet, "/api/v1/admin/fleet", adminToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("fleet = %d", rec.Code)
	}
}

// A fingerprint in a path may be in the URL-safe alphabet, or in the
// standard one, as the UI's copy button copies it, with its slashes
// escaped.
func TestKeyStatus_FingerprintInEitherAlphabet(t *testing.T) {
	kh := newKeyHarness(t)
	fp := "SHA256:ab/cd+ef/gh="
	if _, err := kh.store.PutKeyIfAbsent(context.Background(), store.KeyRecord{Fingerprint: fp}); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{
		"/api/v1/admin/keys/SHA256:ab%2Fcd+ef%2Fgh=/revoke":       store.KeyRevoked,
		"/api/v1/admin/keys/SHA256:ab_cd-ef_gh=/reinstate":        store.KeyActive,
		"/api/v1/admin/keys/SHA256%3Aab%2Fcd%2Bef%2Fgh%3D/revoke": store.KeyRevoked,
	} {
		rec := kh.do(http.MethodPost, path, adminToken, nil)
		if v := decode[keyStatusView](t, rec); rec.Code != http.StatusOK || v.Fingerprint != fp || v.Status != want {
			t.Fatalf("%s = %d %+v", path, rec.Code, v)
		}
	}
}

func TestKeyStatus_RevokedKeyIsNeverRestored(t *testing.T) {
	kh := newKeyHarness(t)
	ka := newTestKey(t, time.Now().Add(-2*time.Hour))
	kb := newTestKey(t, time.Now().Add(-time.Hour))
	kh.checkIn("a", "720h0m0s", ka, kb)
	for _, k := range []testKey{ka, kb} {
		if code := kh.upload("a", k); code != http.StatusOK {
			t.Fatalf("upload = %d", code)
		}
	}
	if rec := kh.setStatus(kb.Fingerprint, "revoke"); rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d %s", rec.Code, rec.Body)
	}

	// b lacks kb, which is revoked: it is not missing it, nor sent it
	kh.checkIn("b", "0s", ka)
	if cmds := kh.poll("b"); len(cmds) != 0 {
		t.Fatalf("b commands = %+v", cmds)
	}
	if got := fleetAgent(t, kh.fleet(), "b").MissingKeys; len(got) != 0 {
		t.Fatalf("b missing = %v", got)
	}
	// a restore queued before the key was revoked cannot fetch it
	if rec := kh.download("b", kb.Fingerprint); rec.Code != http.StatusGone {
		t.Fatalf("download of a revoked key = %d", rec.Code)
	}
	if rec := kh.download("b", ka.Fingerprint); rec.Code != http.StatusOK {
		t.Fatalf("download of an active key = %d", rec.Code)
	}
	// a is not asked to escrow more copies of it
	if got := kh.checkIn("a", "720h0m0s", ka, kb).EscrowNeeded; slices.Contains(got, kb.Fingerprint) {
		t.Fatalf("a escrow_needed = %v", got)
	}

	// its escrowed copy was kept, so once reinstated it is restored
	if rec := kh.setStatus(kb.Fingerprint, "reinstate"); rec.Code != http.StatusOK {
		t.Fatalf("reinstate = %d", rec.Code)
	}
	kh.checkIn("b", "0s", ka)
	cmds := kh.poll("b")
	if len(cmds) != 1 || cmds[0].Type != protocol.CommandKeysRestore || !strings.Contains(string(cmds[0].Payload), kb.Fingerprint) {
		t.Fatalf("b commands after reinstating = %+v", cmds)
	}
	if rec := kh.download("b", kb.Fingerprint); rec.Code != http.StatusOK {
		t.Fatalf("download of a reinstated key = %d", rec.Code)
	}
}

func TestEscrow_CopiesAndRestoreRotation(t *testing.T) {
	kh := newKeyHarness(t)
	kb := newTestKey(t, time.Now().Add(-time.Hour))

	// a reports b's key, whose certificate is public, and escrows a copy
	// that will not open first
	if got := kh.checkIn("a", "720h0m0s", kb).EscrowNeeded; !slices.Equal(got, []string{kb.Fingerprint}) {
		t.Fatalf("a escrow_needed = %v", got)
	}
	garbage, err := envelope.Seal(context.Background(), kh.kms, "escrow", []byte("not a key"), escrowContext("dev", kb.Fingerprint))
	if err != nil {
		t.Fatal(err)
	}
	path := "/agent/v1/escrow/" + protocol.FingerprintPath(kb.Fingerprint)
	if rec := kh.do(http.MethodPut, path, kh.sessions["a"], protocol.EscrowUpload{Certificate: kb.Certificate, Envelope: garbage}); rec.Code != http.StatusOK {
		t.Fatalf("garbage upload = %d", rec.Code)
	}
	// b, which holds the key, still escrows its own copy
	if got := kh.checkIn("b", "0s", kb).EscrowNeeded; !slices.Equal(got, []string{kb.Fingerprint}) {
		t.Fatalf("b escrow_needed = %v", got)
	}
	if code := kh.upload("b", kb); code != http.StatusOK {
		t.Fatalf("b upload = %d", code)
	}
	if got := kh.checkIn("b", "0s", kb).EscrowNeeded; len(got) != 0 {
		t.Fatalf("b escrow_needed after its upload = %v", got)
	}
	if recs, _ := kh.store.Escrow(context.Background(), kb.Fingerprint); len(recs) != 2 {
		t.Fatalf("copies = %d, want 2", len(recs))
	}
	if k := fleetKey(t, kh.fleet(), kb.Fingerprint); k.EscrowCopies != 2 {
		t.Fatalf("escrow copies in the fleet = %d", k.EscrowCopies)
	}
	// the alert is for a key's first copy; later ones are logged as copies
	logs := kh.logs.String()
	if strings.Count(logs, "event=key.escrowed") != 1 || strings.Count(logs, "event=key.escrow_copied") != 1 {
		t.Fatalf("key.escrowed logged %d times and key.escrow_copied %d, want 1 each",
			strings.Count(logs, "event=key.escrowed"), strings.Count(logs, "event=key.escrow_copied"))
	}

	// a restore gets the first copy; after the copy fails, another
	got := func() string {
		t.Helper()
		rec := kh.download("a", kb.Fingerprint)
		if rec.Code != http.StatusOK {
			t.Fatalf("download = %d", rec.Code)
		}
		return decode[protocol.EscrowRecord](t, rec).UploadedBy
	}
	// failRestore runs a restore of kb on a that fails as f says, through
	// the agent API, and waits for its retry
	failRestore := func(f protocol.KeyFailure) {
		t.Helper()
		now := kh.clock()
		body, _ := json.Marshal(protocol.KeysRestorePayload{Fingerprints: []string{kb.Fingerprint}})
		id := ulid.Make().String()
		err := kh.store.PutCommand(context.Background(), store.CommandRecord{
			AgentID: "a", ID: id, Type: protocol.CommandKeysRestore, Status: store.CommandQueued,
			CreatedAt: now, ExpiresAt: now.Add(keyCommandTTL), Payload: string(body),
		})
		if err != nil {
			t.Fatal(err)
		}
		if cmds := kh.poll("a"); len(cmds) != 1 || cmds[0].ID != id {
			t.Fatalf("a commands = %+v", cmds)
		}
		f.Fingerprint = kb.Fingerprint
		res, _ := json.Marshal(protocol.KeysRestoreResult{Failed: []protocol.KeyFailure{f}})
		if code := kh.result("a", id, protocol.CommandResult{Status: protocol.CommandFailed, Error: "failed to restore 1 of 1 keys", Result: res}); code != http.StatusOK {
			t.Fatalf("restore result = %d", code)
		}
		kh.advance(retryAfterFailure)
	}
	if by := got(); by != "a" {
		t.Fatalf("first download from %s, want a's (the primary)", by)
	}
	// the downloads of one restore read the agent's commands once
	reads := kh.faulty.commandReads.Load()
	got()
	if n := kh.faulty.commandReads.Load() - reads; n != 0 {
		t.Fatalf("a second download read the agent's commands %d times", n)
	}
	// a failure that was not the copy's keeps it
	failRestore(protocol.KeyFailure{Error: "failed to create key secret in sealed-secrets: forbidden", UploadedBy: "a"})
	if by := got(); by != "a" {
		t.Fatalf("download after a failure not the copy's from %s, want a's", by)
	}
	// a failure from an older agent, which names no copy, moves on to the
	// next copy
	failRestore(protocol.KeyFailure{Error: "escrowed private key does not match its certificate"})
	if by := got(); by != "b" {
		t.Fatalf("download after an older agent's failure from %s, want b's", by)
	}
	// a copy found bad is skipped, exactly that copy
	failRestore(protocol.KeyFailure{Error: "escrowed private key does not match its certificate", UploadedBy: "b", BadCopy: true})
	if by := got(); by != "a" {
		t.Fatalf("download after b's copy failed from %s, want a's", by)
	}
	// with every copy found bad, it goes round them all
	failRestore(protocol.KeyFailure{Error: "failed to unwrap data key", UploadedBy: "a", BadCopy: true})
	if by := got(); by != "b" {
		t.Fatalf("download after every copy failed from %s, want b's", by)
	}
	logs = kh.logs.String()
	if !strings.Contains(logs, "uploaded_by=b") {
		t.Error("key.escrow_read does not name the copy's uploader")
	}
	if !strings.Contains(logs, "bad_copy=true") {
		t.Error("key.sync_failed does not say the copy was at fault")
	}
}

func TestCheckIn_RebuiltClusterJoinsWithoutBlockingTheEnv(t *testing.T) {
	kh := newKeyHarness(t)
	ka := newTestKey(t, time.Now().Add(-48*time.Hour))
	kh.checkIn("a", "720h0m0s", ka)
	kh.checkIn("b", "0s", ka)
	if code := kh.upload("a", ka); code != http.StatusOK {
		t.Fatalf("upload = %d", code)
	}
	kh.poll("a") // renewal.enable.v1
	// long after both joined
	kh.advance(fleet.JoinWindow)
	kh.checkIn("a", "720h0m0s", ka)
	kh.checkIn("b", "0s", ka)
	if b := fleetAgent(t, kh.fleet(), "b"); b.Joining || b.JoinedAt == nil {
		t.Fatalf("b = joining %v, joined %v", b.Joining, b.JoinedAt)
	}

	// b's cluster is rebuilt: its new controller has only a fresh key
	fresh := newTestKey(t, time.Now())
	kh.checkIn("b", "0s", fresh)
	f := kh.fleet()
	b := fleetAgent(t, f, "b")
	if !b.Joining || b.JoinedAt == nil || !b.JoinedAt.Equal(kh.clock()) {
		t.Fatalf("rebuilt b = joining %v, joined %v", b.Joining, b.JoinedAt)
	}
	// the env key stays, and b's fresh key does not become it
	if f.EnvKey == nil || f.EnvKey.Fingerprint != ka.Fingerprint {
		t.Fatalf("env key = %+v, want ka", f.EnvKey)
	}
	rec := kh.userDo("bob", http.MethodGet, "/api/v1/status", false)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "key sync") {
		t.Fatalf("status = %d %s", rec.Code, rec.Body)
	}
	// restore catches b up
	cmds := kh.poll("b")
	if len(cmds) != 1 || cmds[0].Type != protocol.CommandKeysRestore || !strings.Contains(string(cmds[0].Payload), ka.Fingerprint) {
		t.Fatalf("b commands = %+v", cmds)
	}

	// if it has not caught up when the window ends, it counts again, and
	// the fleet says why the env is out of sync
	kh.advance(fleet.JoinWindow)
	kh.checkIn("a", "720h0m0s", ka)
	kh.checkIn("b", "0s", fresh)
	f = kh.fleet()
	b = fleetAgent(t, f, "b")
	if b.Joining || f.EnvKey != nil || !strings.Contains(strings.Join(b.Issues, ";"), "holds back the env key") {
		t.Fatalf("b after the window = joining %v, env key %+v, issues %v", b.Joining, f.EnvKey, b.Issues)
	}
}

// A check-in that cannot read the fleet is stored all the same, so the agent
// stays healthy; key sync waits for the next one, and the join time, which
// needs the agent's previous state, is unknown.
func TestCheckIn_StoredWhenTheFleetCannotBeRead(t *testing.T) {
	kh := newKeyHarness(t)
	ka := newTestKey(t, time.Now().Add(-time.Hour))
	kh.checkIn("a", "720h0m0s", ka)
	kh.advance(time.Minute)

	kh.faulty.failStateReads.Store(true)
	if got := kh.checkIn("a", "720h0m0s", ka).EscrowNeeded; len(got) != 0 {
		t.Fatalf("escrow_needed without key sync = %v", got)
	}
	kh.faulty.failStateReads.Store(false)
	states, _ := kh.store.GetAgentStates(context.Background(), []string{"a"})
	if s := states["a"]; !s.LastCheckIn.Equal(kh.clock()) || s.JoinedAt != nil || len(s.Keys) != 1 {
		t.Fatalf("state = %+v", s)
	}
	if !strings.Contains(kh.logs.String(), "event=key.sync_failed") {
		t.Error("the skipped key sync was not logged")
	}
	// the next check-in syncs keys again
	if got := kh.checkIn("a", "720h0m0s", ka).EscrowNeeded; !slices.Equal(got, []string{ka.Fingerprint}) {
		t.Fatalf("escrow_needed = %v", got)
	}
}

// manyKeys returns n sealing keys an hour apart, the newest an hour old,
// oldest first. Keys are made in parallel: hundreds take a while.
func manyKeys(t *testing.T, n int) []protocol.Key {
	t.Helper()
	privs := make([]*rsa.PrivateKey, n)
	var wg sync.WaitGroup
	var failed atomic.Bool
	for i := range n {
		wg.Go(func() {
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				failed.Store(true)
			}
			privs[i] = k
		})
	}
	wg.Wait()
	if failed.Load() {
		t.Fatal("failed to generate keys")
	}
	start := time.Now().Add(-time.Duration(n) * time.Hour)
	out := make([]protocol.Key, n)
	for i, priv := range privs {
		pem := testcerts.SelfSigned(t, priv, start.Add(time.Duration(i)*time.Hour))
		k, _, err := keys.ParseCert(pem)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = protocol.Key{Fingerprint: k.Fingerprint, NotBefore: k.NotBefore, NotAfter: k.NotAfter, Certificate: string(pem)}
	}
	return out
}

func TestCheckIn_KeepsTheNewestKeysOverTheLimit(t *testing.T) {
	h := newHarness(t, adminToken)
	session := h.login()
	ks := manyKeys(t, protocol.MaxKeys+1)
	checkInWith := func(n int) {
		t.Helper()
		if rec := h.do(http.MethodPost, "/agent/v1/checkin", session, checkIn(ks[len(ks)-n:]...)); rec.Code != http.StatusOK {
			t.Fatalf("check-in with %d keys = %d %s", n, rec.Code, rec.Body)
		}
	}
	count := func(event string) int { return strings.Count(h.logs.String(), "event="+event) }

	// a warning at half the limit, and at 80%, each once
	checkInWith(protocol.MaxKeys / 2)
	checkInWith(protocol.MaxKeys / 2)
	if n := count("keys.near_limit"); n != 1 || !strings.Contains(h.logs.String(), "percent=50") {
		t.Fatalf("keys.near_limit logged %d times at half the limit", n)
	}
	checkInWith(protocol.MaxKeys * 4 / 5)
	if n := count("keys.near_limit"); n != 2 || !strings.Contains(h.logs.String(), "percent=80") {
		t.Fatalf("keys.near_limit logged %d times at 80%%", n)
	}

	// over the limit, the check-in is accepted and the oldest key left out
	checkInWith(len(ks))
	checkInWith(len(ks))
	if n := count("keys.truncated"); n != 1 {
		t.Fatalf("keys.truncated logged %d times, want 1", n)
	}
	states, _ := h.store.GetAgentStates(context.Background(), []string{"use1-blue"})
	s := states["use1-blue"]
	if len(s.Keys) != protocol.MaxKeys || s.KeysReported != protocol.MaxKeys+1 ||
		s.DroppedUpTo == nil || !s.DroppedUpTo.Equal(ks[0].NotBefore) || containsKey(s.Keys, ks[0].Fingerprint) {
		t.Fatalf("state = %d keys of %d reported, dropped up to %v", len(s.Keys), s.KeysReported, s.DroppedUpTo)
	}
	if _, ok := h.store.Key(ks[0].Fingerprint); ok {
		t.Error("a key left out was recorded")
	}
	f := decode[fleet.Fleet](t, h.do(http.MethodGet, "/api/v1/admin/fleet", adminToken, nil))
	if a := f.Agents[0]; a.KeysDropped != 1 || a.KeysReported != protocol.MaxKeys+1 || f.KeyLimit != protocol.MaxKeys {
		t.Fatalf("fleet agent = dropped %d of %d, limit %d", a.KeysDropped, a.KeysReported, f.KeyLimit)
	}
}

func TestCheckIn_FutureDatedKeyAndKeyOrderAreFlaggedOnce(t *testing.T) {
	h := newHarness(t, adminToken)
	session := h.login()
	current := protoKey(t, time.Now().Add(-time.Hour))
	planted := protoKey(t, time.Now().Add(48*time.Hour))
	in := checkIn(current, planted)
	in.Commands = []string{protocol.CommandKeysRestore}
	in.Controller.KeyOrderPriority = "SecretCreationTimestamp"
	var resp protocol.CheckInResponse
	for range 2 {
		rec := h.do(http.MethodPost, "/agent/v1/checkin", session, in)
		if rec.Code != http.StatusOK {
			t.Fatalf("check-in = %d %s", rec.Code, rec.Body)
		}
		resp = decode[protocol.CheckInResponse](t, rec)
	}
	for event, want := range map[string]int{"key.future_dated": 1, "key.order_mismatch": 1} {
		if n := strings.Count(h.logs.String(), "event="+event); n != want {
			t.Errorf("%s logged %d times, want %d", event, n, want)
		}
	}
	// a key dated in the future is not escrowed until its time
	if !slices.Equal(resp.EscrowNeeded, []string{current.Fingerprint}) {
		t.Errorf("escrow_needed = %v", resp.EscrowNeeded)
	}
	f := decode[fleet.Fleet](t, h.do(http.MethodGet, "/api/v1/admin/fleet", adminToken, nil))
	if k := fleetKey(t, f, planted.Fingerprint); !k.FutureDated {
		t.Errorf("planted key = %+v", k)
	}
}

func TestPlanKeySync_EscrowCopiesAndRestoreOrder(t *testing.T) {
	reg, err := registry.Parse([]byte(`
issuers: [{name: local, url: "https://k8s.example.com", jwksFile: k.json}]
agents:
  - {id: a, cluster: a, region: use1, capabilities: [seal, keys], identity: {k8s: {issuer: local, subject: "system:serviceaccount:a:agent"}}}
  - {id: b, cluster: b, region: use1, capabilities: [seal, keys], identity: {k8s: {issuer: local, subject: "system:serviceaccount:b:agent"}}}
`), "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	ref := func(fp string, age time.Duration) store.KeyRef {
		return store.KeyRef{Fingerprint: fp, NotBefore: now.Add(-age), NotAfter: now.Add(time.Hour)}
	}
	st := func(id string, ks ...store.KeyRef) store.AgentState {
		return store.AgentState{
			AgentID: id, LastCheckIn: now, KeysComplete: true,
			Capabilities: []string{protocol.CapabilitySeal, protocol.CapabilityKeys},
			Commands:     []string{protocol.CommandKeysRestore},
			Controller:   protocol.Controller{KeyRenewPeriod: "720h0m0s", KeyOrderPriority: "CertNotBefore"},
			Keys:         ks,
		}
	}
	mine, full, theirs := ref("SHA256:mine", 3*time.Hour), ref("SHA256:full", 2*time.Hour), ref("SHA256:theirs", time.Hour)
	revoked, future := ref("SHA256:revoked", 4*time.Hour), ref("SHA256:future", -48*time.Hour)
	older, newer := ref("SHA256:older", 10*time.Hour), ref("SHA256:newer", 30*time.Minute)
	states := map[string]store.AgentState{
		"a": st("a", mine, full, theirs, revoked, future),
		"b": st("b", mine, full, theirs, older, newer),
	}
	keys := fleet.Keys{
		Revoked: map[string]store.RevokedKey{revoked.Fingerprint: {Fingerprint: revoked.Fingerprint}},
		Escrow: map[string][]string{
			mine.Fingerprint:   {"a"},
			full.Fingerprint:   {"b", "c", "d"},
			theirs.Fingerprint: {"b"},
			older.Fingerprint:  {"b"},
			newer.Fingerprint:  {"b"},
		},
	}
	self, _ := reg.Agent("a")
	plan := planKeySync(fleet.Compute("dev", reg, states, keys, now), self, states["a"], false, nil, keys, now)
	// a adds its copy where it has none and the key has room; not of
	// revoked or future-dated keys
	if !slices.Equal(plan.EscrowNeeded, []string{theirs.Fingerprint}) {
		t.Errorf("escrow needed = %v, want [theirs]", plan.EscrowNeeded)
	}
	// the newest missing key is restored first
	if !slices.Equal(plan.Restore, []string{newer.Fingerprint, older.Fingerprint}) {
		t.Errorf("restore = %v, want [newer older]", plan.Restore)
	}

	// further copies are asked for a few at a time; first copies are not
	// held back
	var many []store.KeyRef
	for i := range maxCopiesPerCheckIn + 5 {
		k := ref(fmt.Sprintf("SHA256:copy-%02d", i), time.Duration(i+1)*time.Minute)
		many = append(many, k)
		keys.Escrow[k.Fingerprint] = []string{"b"}
	}
	for i := range 5 {
		many = append(many, ref(fmt.Sprintf("SHA256:first-%02d", i), time.Hour))
	}
	states["a"] = st("a", many...)
	plan = planKeySync(fleet.Compute("dev", reg, states, keys, now), self, states["a"], false, nil, keys, now)
	if len(plan.EscrowNeeded) != maxCopiesPerCheckIn+5 || !slices.Contains(plan.EscrowNeeded, "SHA256:first-04") {
		t.Errorf("escrow needed = %d keys %v, want %d copies and the 5 first copies", len(plan.EscrowNeeded), plan.EscrowNeeded, maxCopiesPerCheckIn)
	}
}

// A cluster missing more keys than one restore carries gets them a command
// at a time: each restore ends in a controller restart, so the next waits
// until the last has settled. An agent that cannot tell its controller's
// key order gets none, since it would refuse them.
func TestPlanKeySync_OneRestoreAtATime(t *testing.T) {
	reg, err := registry.Parse([]byte(`
issuers: [{name: local, url: "https://k8s.example.com", jwksFile: k.json}]
agents:
  - {id: a, cluster: a, region: use1, capabilities: [seal, keys], identity: {k8s: {issuer: local, subject: "system:serviceaccount:a:agent"}}}
  - {id: b, cluster: b, region: use1, capabilities: [seal, keys], identity: {k8s: {issuer: local, subject: "system:serviceaccount:b:agent"}}}
`), "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	st := func(id string, ks ...store.KeyRef) store.AgentState {
		return store.AgentState{
			AgentID: id, LastCheckIn: now, KeysComplete: true,
			Capabilities: []string{protocol.CapabilitySeal, protocol.CapabilityKeys},
			Commands:     []string{protocol.CommandKeysRestore},
			Controller:   protocol.Controller{KeyRenewPeriod: "720h0m0s", KeyOrderPriority: "CertNotBefore"},
			Keys:         ks,
		}
	}
	keys := fleet.Keys{Escrow: map[string][]string{}}
	var held []store.KeyRef
	for i := range protocol.MaxRestoreKeys + 50 {
		nb := now.Add(-time.Duration(1000-i) * time.Hour)
		k := store.KeyRef{Fingerprint: fmt.Sprintf("SHA256:k%03d", i), NotBefore: nb, NotAfter: nb.AddDate(1, 0, 0)}
		held = append(held, k)
		keys.Escrow[k.Fingerprint] = []string{"a"}
	}
	fresh := store.KeyRef{Fingerprint: "SHA256:fresh", NotBefore: now, NotAfter: now.AddDate(1, 0, 0)}
	states := map[string]store.AgentState{"a": st("a", held...), "b": st("b", fresh)}
	self, _ := reg.Agent("b")
	plan := func(commands ...store.CommandRecord) []string {
		t.Helper()
		return planKeySync(fleet.Compute("dev", reg, states, keys, now), self, states["b"], false, commands, keys, now).Restore
	}

	first := plan()
	if len(first) != protocol.MaxRestoreKeys {
		t.Fatalf("first restore = %d keys, want %d", len(first), protocol.MaxRestoreKeys)
	}
	body, _ := json.Marshal(protocol.KeysRestorePayload{Fingerprints: first})
	cmd := store.CommandRecord{
		AgentID: "b", ID: ulid.Make().String(), Type: protocol.CommandKeysRestore, Status: store.CommandQueued,
		CreatedAt: now, ExpiresAt: now.Add(keyCommandTTL), Payload: string(body),
	}
	// while it is open or settling, not even the keys it left out are sent
	if got := plan(cmd); len(got) != 0 {
		t.Fatalf("restore while one is open = %d keys", len(got))
	}
	finished := now.Add(-time.Minute)
	cmd.Status, cmd.FinishedAt = store.CommandSucceeded, &finished
	if got := plan(cmd); len(got) != 0 {
		t.Fatalf("restore while one settles = %d keys", len(got))
	}
	// once it has settled, the next goes out
	finished = now.Add(-settleAfterSuccess - time.Second)
	if got := plan(cmd); len(got) == 0 {
		t.Fatal("no restore once the last settled")
	}

	unknown := states["b"]
	unknown.Controller.KeyOrderPriority = ""
	states["b"] = unknown
	if got := plan(); len(got) != 0 {
		t.Fatalf("restore with the key order unknown = %d keys", len(got))
	}
}
