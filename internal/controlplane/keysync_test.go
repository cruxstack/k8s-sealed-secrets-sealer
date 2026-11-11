package controlplane

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
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
)

// syncHarness is an env of three agents:
//
//	a: seal, keys, renewal
//	b: seal, keys
//	c: seal
type syncHarness struct {
	*harness
	srv      *Server
	sessions map[string]string
	kms      *envelope.FakeKMS

	mu  sync.Mutex
	now time.Time
}

func newSyncHarness(t *testing.T) *syncHarness {
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
	logs := &bytes.Buffer{}
	mem := store.NewMemory()
	sh := &syncHarness{sessions: map[string]string{}, kms: envelope.NewFakeKMS("escrow"), now: time.Now().UTC()}
	sh.srv = New(Options{
		Logger:       slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Env:          "dev",
		Registry:     reg,
		Sessions:     sessions,
		Store:        mem,
		PollInterval: 10 * time.Millisecond,
		AdminToken:   adminToken,
		Now:          sh.clock,
	})
	sh.harness = &harness{t: t, h: sh.srv.Handler(), store: mem, logs: logs}
	for _, id := range []string{"a", "b", "c"} {
		token, _, err := sessions.Issue(id)
		if err != nil {
			t.Fatal(err)
		}
		sh.sessions[id] = token
	}
	return sh
}

func (sh *syncHarness) clock() time.Time {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	return sh.now
}

func (sh *syncHarness) advance(d time.Duration) {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	sh.now = sh.now.Add(d)
}

// testKey is a sealing key with its private half.
type testKey struct {
	protocol.Key
	PrivatePEM []byte
}

func newTestKey(t *testing.T, notBefore time.Time) testKey {
	t.Helper()
	priv := testcerts.RSA(t, 2048)
	certPEM := testcerts.SelfSigned(t, priv, notBefore)
	k, _, err := keys.ParseCert(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{
		Key:        protocol.Key{Fingerprint: k.Fingerprint, NotBefore: k.NotBefore, NotAfter: k.NotAfter, Certificate: string(certPEM)},
		PrivatePEM: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}),
	}
}

// checkIn checks in as an agent with the capabilities the harness
// registry grants, handling every key command.
func (sh *syncHarness) checkIn(id, renew string, ks ...testKey) protocol.CheckInResponse {
	sh.t.Helper()
	in := checkIn(protoKeys(ks)...)
	in.Controller.KeyRenewPeriod = renew
	switch id {
	case "a":
		in.Capabilities = []string{protocol.CapabilitySeal, protocol.CapabilityKeys, protocol.CapabilityRenewal}
		in.Commands = []string{protocol.CommandKeysRestore, protocol.CommandRenewalEnable}
	case "b":
		in.Capabilities = []string{protocol.CapabilitySeal, protocol.CapabilityKeys}
		in.Commands = []string{protocol.CommandKeysRestore}
	default:
		in.Capabilities = []string{protocol.CapabilitySeal}
		in.KeysComplete = false
		in.Keys = in.Keys[len(in.Keys)-1:]
	}
	rec := sh.do(http.MethodPost, "/agent/v1/checkin", sh.sessions[id], in)
	if rec.Code != http.StatusOK {
		sh.t.Fatalf("check-in %s = %d %s", id, rec.Code, rec.Body)
	}
	var resp protocol.CheckInResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		sh.t.Fatal(err)
	}
	return resp
}

func protoKeys(ks []testKey) []protocol.Key {
	out := make([]protocol.Key, len(ks))
	for i, k := range ks {
		out[i] = k.Key
	}
	return out
}

func (sh *syncHarness) upload(id string, k testKey) int {
	sh.t.Helper()
	env, err := envelope.Seal(context.Background(), sh.kms, "escrow", append([]byte(k.Certificate), k.PrivatePEM...), escrowContext("dev", k.Fingerprint))
	if err != nil {
		sh.t.Fatal(err)
	}
	rec := sh.do(http.MethodPut, "/agent/v1/escrow/"+protocol.FingerprintPath(k.Fingerprint), sh.sessions[id],
		protocol.EscrowUpload{Certificate: k.Certificate, Envelope: env})
	return rec.Code
}

func (sh *syncHarness) poll(id string) []protocol.Command {
	sh.t.Helper()
	rec := sh.do(http.MethodGet, "/agent/v1/commands?wait=0", sh.sessions[id], nil)
	if rec.Code != http.StatusOK {
		sh.t.Fatalf("poll %s = %d %s", id, rec.Code, rec.Body)
	}
	var resp protocol.CommandsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		sh.t.Fatal(err)
	}
	return resp.Commands
}

func (sh *syncHarness) result(id, commandID string, res protocol.CommandResult) int {
	sh.t.Helper()
	return sh.do(http.MethodPost, "/agent/v1/commands/"+commandID+"/result", sh.sessions[id], res).Code
}

func TestKeySync_EscrowRestoreAndRenewal(t *testing.T) {
	sh := newSyncHarness(t)
	ka := newTestKey(t, time.Now().Add(-2*time.Hour))
	kb := newTestKey(t, time.Now().Add(-time.Hour))

	// a and b each start with their own key, renewal off everywhere
	if got := sh.checkIn("a", "0s", ka).EscrowNeeded; !slices.Equal(got, []string{ka.Fingerprint}) {
		t.Fatalf("a escrow_needed = %v", got)
	}
	if got := sh.checkIn("b", "0s", kb).EscrowNeeded; !slices.Equal(got, []string{kb.Fingerprint}) {
		t.Fatalf("b escrow_needed = %v", got)
	}
	// c (seal only) is never asked to escrow
	if got := sh.checkIn("c", "0s", kb).EscrowNeeded; len(got) != 0 {
		t.Fatalf("c escrow_needed = %v", got)
	}

	// a is the only agent able to renew, so it is asked to, at its next
	// check-in: never on a first one
	if cmds := sh.poll("a"); len(cmds) != 0 {
		t.Fatalf("a commands after its first check-in = %+v", cmds)
	}
	sh.checkIn("a", "0s", ka)
	cmds := sh.poll("a")
	if len(cmds) != 1 || cmds[0].Type != protocol.CommandRenewalEnable {
		t.Fatalf("a commands = %+v", cmds)
	}
	var renewal protocol.RenewalEnablePayload
	if err := json.Unmarshal(cmds[0].Payload, &renewal); err != nil || renewal.Period != "720h0m0s" {
		t.Fatalf("renewal payload = %s", cmds[0].Payload)
	}
	// leased once
	if again := sh.poll("a"); len(again) != 0 {
		t.Fatalf("command delivered twice: %+v", again)
	}
	if code := sh.result("a", cmds[0].ID, protocol.CommandResult{Status: protocol.CommandSucceeded}); code != http.StatusOK {
		t.Fatalf("renewal result = %d", code)
	}
	if code := sh.result("a", cmds[0].ID, protocol.CommandResult{Status: protocol.CommandSucceeded}); code != http.StatusConflict {
		t.Fatalf("second result = %d, want 409", code)
	}
	// until a's next inventory reports it, renewal is not asked for again
	sh.checkIn("a", "0s", ka)
	if cmds := sh.poll("a"); len(cmds) != 0 {
		t.Fatalf("renewal re-queued before it settled: %+v", cmds)
	}

	// escrow both keys; nothing to restore until then
	if cmds := sh.poll("b"); len(cmds) != 0 {
		t.Fatalf("b commands before escrow = %+v", cmds)
	}
	if code := sh.upload("a", ka); code != http.StatusOK {
		t.Fatalf("upload a = %d", code)
	}
	if code := sh.upload("b", kb); code != http.StatusOK {
		t.Fatalf("upload b = %d", code)
	}
	if got := sh.checkIn("a", "720h0m0s", ka).EscrowNeeded; len(got) != 0 {
		t.Fatalf("a escrow_needed after upload = %v", got)
	}

	// a is missing kb, b is missing ka: each is asked to restore
	sh.checkIn("b", "0s", kb)
	for id, want := range map[string]string{"a": kb.Fingerprint, "b": ka.Fingerprint} {
		cmds := sh.poll(id)
		if len(cmds) != 1 || cmds[0].Type != protocol.CommandKeysRestore {
			t.Fatalf("%s commands = %+v", id, cmds)
		}
		var p protocol.KeysRestorePayload
		if err := json.Unmarshal(cmds[0].Payload, &p); err != nil || !slices.Equal(p.Fingerprints, []string{want}) {
			t.Fatalf("%s restore payload = %s", id, cmds[0].Payload)
		}
		res, _ := json.Marshal(protocol.KeysRestoreResult{Restored: p.Fingerprints, ControllerRestarted: true})
		if code := sh.result(id, cmds[0].ID, protocol.CommandResult{Status: protocol.CommandSucceeded, Result: res}); code != http.StatusOK {
			t.Fatalf("%s restore result = %d", id, code)
		}
	}
	// a check-in that still predates the restore does not re-queue it
	sh.checkIn("b", "0s", kb)
	if cmds := sh.poll("b"); len(cmds) != 0 {
		t.Fatalf("restore re-queued before it settled: %+v", cmds)
	}
	// once settled, a key still missing is restored again
	sh.advance(settleAfterSuccess + time.Second)
	sh.checkIn("a", "720h0m0s", ka, kb)
	sh.checkIn("b", "0s", kb)
	if cmds := sh.poll("b"); len(cmds) != 1 || cmds[0].Type != protocol.CommandKeysRestore {
		t.Fatalf("b commands after settling = %+v", cmds)
	}
	// c cannot run key commands and is never sent any
	if cmds := sh.poll("c"); len(cmds) != 0 {
		t.Fatalf("c commands = %+v", cmds)
	}

	logs := sh.logs.String()
	for _, event := range []string{"event=key.escrowed", "event=key.restored", "event=renewal.enabled", "event=key.restore_queued", "event=renewal.enable_queued"} {
		if !strings.Contains(logs, event) {
			t.Errorf("%s was not logged", event)
		}
	}
}

// A key that a restore found already in the cluster, held under another
// label, while the agent still does not report it, is not restored again
// for an hour, and the fleet says why. The restore is older than what every
// check-in reads back.
func TestKeySync_HoldsKeysFoundPresent(t *testing.T) {
	sh := newSyncHarness(t)
	ka := newTestKey(t, time.Now().Add(-2*time.Hour))
	kb := newTestKey(t, time.Now().Add(-time.Hour))
	sh.checkIn("a", "720h0m0s", ka, kb)
	for _, k := range []testKey{ka, kb} {
		if code := sh.upload("a", k); code != http.StatusOK {
			t.Fatalf("upload = %d", code)
		}
	}
	created := time.Now().Add(-30 * time.Minute)
	finished := sh.clock().Add(-20 * time.Minute)
	payload, _ := json.Marshal(protocol.KeysRestorePayload{Fingerprints: []string{ka.Fingerprint}})
	res, _ := json.Marshal(protocol.KeysRestoreResult{Restored: []string{}, AlreadyPresent: []string{ka.Fingerprint}, Failed: []protocol.KeyFailure{}})
	if err := sh.store.PutCommand(context.Background(), store.CommandRecord{
		AgentID: "b", ID: ulid.MustNew(ulid.Timestamp(created), ulid.DefaultEntropy()).String(), Type: protocol.CommandKeysRestore,
		Status: store.CommandSucceeded, CreatedAt: created, ExpiresAt: created.Add(keyCommandTTL), FinishedAt: &finished,
		Payload: string(payload), Result: string(res),
	}); err != nil {
		t.Fatal(err)
	}

	sh.checkIn("b", "0s", kb)
	if cmds := sh.poll("b"); len(cmds) != 0 {
		t.Fatalf("restored a key found present %s ago: %+v", 20*time.Minute, cmds)
	}
	f := decode[fleet.Fleet](t, sh.do(http.MethodGet, "/api/v1/admin/fleet", adminToken, nil))
	var issues []string
	for _, a := range f.Agents {
		if a.ID == "b" {
			issues = a.Issues
		}
	}
	if !slices.ContainsFunc(issues, func(s string) bool {
		return strings.Contains(s, ka.Fingerprint) && strings.Contains(s, "already in its cluster")
	}) {
		t.Fatalf("b's issues = %q", issues)
	}

	// an hour after the restore, it is tried again
	sh.advance(presentHold - 20*time.Minute + time.Second)
	sh.checkIn("a", "720h0m0s", ka, kb)
	sh.checkIn("b", "0s", kb)
	if cmds := sh.poll("b"); len(cmds) != 1 || cmds[0].Type != protocol.CommandKeysRestore {
		t.Fatalf("b commands after the hold = %+v", cmds)
	}
}

func TestEscrow_Rejects(t *testing.T) {
	sh := newSyncHarness(t)
	k := newTestKey(t, time.Now().Add(-time.Hour))
	other := newTestKey(t, time.Now().Add(-time.Hour))
	sh.checkIn("a", "720h0m0s", k)
	sh.checkIn("c", "720h0m0s", k)

	good, err := envelope.Seal(context.Background(), sh.kms, "escrow", []byte("key"), escrowContext("dev", k.Fingerprint))
	if err != nil {
		t.Fatal(err)
	}
	put := func(id, fp string, in protocol.EscrowUpload) int {
		return sh.do(http.MethodPut, "/agent/v1/escrow/"+protocol.FingerprintPath(fp), sh.sessions[id], in).Code
	}
	withCtx := func(ctx map[string]string) protocol.EscrowUpload {
		e := good
		e.Context = ctx
		return protocol.EscrowUpload{Certificate: k.Certificate, Envelope: e}
	}
	cases := map[string]struct {
		id, fp string
		in     protocol.EscrowUpload
		want   int
	}{
		"seal-only agent":        {"c", k.Fingerprint, protocol.EscrowUpload{Certificate: k.Certificate, Envelope: good}, http.StatusForbidden},
		"certificate for path":   {"a", other.Fingerprint, protocol.EscrowUpload{Certificate: k.Certificate, Envelope: good}, http.StatusBadRequest},
		"key the agent lacks":    {"a", other.Fingerprint, protocol.EscrowUpload{Certificate: other.Certificate, Envelope: withCtx(escrowContext("dev", other.Fingerprint)).Envelope}, http.StatusConflict},
		"other env":              {"a", k.Fingerprint, withCtx(escrowContext("prod", k.Fingerprint)), http.StatusBadRequest},
		"other fingerprint":      {"a", k.Fingerprint, withCtx(escrowContext("dev", other.Fingerprint)), http.StatusBadRequest},
		"missing purpose":        {"a", k.Fingerprint, withCtx(map[string]string{"env": "dev", "fingerprint": k.Fingerprint}), http.StatusBadRequest},
		"garbage certificate":    {"a", k.Fingerprint, protocol.EscrowUpload{Certificate: "nope", Envelope: good}, http.StatusBadRequest},
		"ciphertext not base64":  {"a", k.Fingerprint, protocol.EscrowUpload{Certificate: k.Certificate, Envelope: func() protocol.Envelope { e := good; e.Ciphertext = "!!"; return e }()}, http.StatusBadRequest},
		"missing wrapped key":    {"a", k.Fingerprint, protocol.EscrowUpload{Certificate: k.Certificate, Envelope: func() protocol.Envelope { e := good; e.WrappedKey = ""; return e }()}, http.StatusBadRequest},
		"missing kms key":        {"a", k.Fingerprint, protocol.EscrowUpload{Certificate: k.Certificate, Envelope: func() protocol.Envelope { e := good; e.KeyID = ""; return e }()}, http.StatusBadRequest},
		"unauthenticated upload": {"nobody", k.Fingerprint, protocol.EscrowUpload{Certificate: k.Certificate, Envelope: good}, http.StatusUnauthorized},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if code := put(tc.id, tc.fp, tc.in); code != tc.want {
				t.Fatalf("status = %d, want %d", code, tc.want)
			}
		})
	}
	if recs, _ := sh.store.Escrow(context.Background(), k.Fingerprint); len(recs) != 0 {
		t.Fatal("a rejected upload was stored")
	}

	// an agent's copy is never replaced
	if code := put("a", k.Fingerprint, protocol.EscrowUpload{Certificate: k.Certificate, Envelope: good}); code != http.StatusOK {
		t.Fatalf("upload = %d", code)
	}
	first, _ := sh.store.Escrow(context.Background(), k.Fingerprint)
	if code := sh.upload("a", k); code != http.StatusOK {
		t.Fatalf("second upload = %d", code)
	}
	if again, _ := sh.store.Escrow(context.Background(), k.Fingerprint); len(again) != 1 || again[0].Envelope.Ciphertext != first[0].Envelope.Ciphertext {
		t.Fatal("a second upload replaced the first")
	}

	// downloads: keys agents only
	path := "/agent/v1/escrow/" + protocol.FingerprintPath(k.Fingerprint)
	if rec := sh.do(http.MethodGet, path, sh.sessions["c"], nil); rec.Code != http.StatusForbidden {
		t.Fatalf("seal-only download = %d", rec.Code)
	}
	rec := sh.do(http.MethodGet, path, sh.sessions["b"], nil)
	var got protocol.EscrowRecord
	if rec.Code != http.StatusOK || json.NewDecoder(rec.Body).Decode(&got) != nil || got.UploadedBy != "a" || got.Fingerprint != k.Fingerprint {
		t.Fatalf("download = %d %+v", rec.Code, got)
	}
	if rec := sh.do(http.MethodGet, "/agent/v1/escrow/"+protocol.FingerprintPath(other.Fingerprint), sh.sessions["b"], nil); rec.Code != http.StatusNotFound {
		t.Fatalf("download of unknown key = %d", rec.Code)
	}
}

func TestCommands_LongPollAndResults(t *testing.T) {
	sh := newSyncHarness(t)
	ctx := context.Background()
	now := sh.clock()
	put := func(agentID, id, typ string, expires time.Time) {
		t.Helper()
		if err := sh.store.PutCommand(ctx, store.CommandRecord{AgentID: agentID, ID: id, Type: typ, Status: store.CommandQueued, CreatedAt: now, ExpiresAt: expires, Payload: `{}`}); err != nil {
			t.Fatal(err)
		}
	}

	// commands are read by when their IDs (ULIDs) were made
	first, expired, other := ulid.Make().String(), ulid.Make().String(), ulid.Make().String()

	// a held poll returns as soon as a command is queued
	done := make(chan []protocol.Command, 1)
	go func() {
		rec := sh.do(http.MethodGet, "/agent/v1/commands?wait=5", sh.sessions["a"], nil)
		var resp protocol.CommandsResponse
		_ = json.NewDecoder(rec.Body).Decode(&resp)
		done <- resp.Commands
	}()
	time.Sleep(50 * time.Millisecond)
	put("a", first, protocol.CommandRenewalEnable, now.Add(time.Minute))
	select {
	case cmds := <-done:
		if len(cmds) != 1 || cmds[0].ID != first {
			t.Fatalf("held poll = %+v", cmds)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("held poll did not return when a command was queued")
	}

	// expired commands, and commands the agent is not registered for, are
	// never delivered
	put("a", expired, protocol.CommandKeysRestore, now.Add(-time.Second))
	put("c", other, protocol.CommandKeysRestore, now.Add(time.Minute))
	if cmds := sh.poll("a"); len(cmds) != 0 {
		t.Fatalf("a commands = %+v", cmds)
	}
	if cmds := sh.poll("c"); len(cmds) != 0 {
		t.Fatalf("c commands = %+v", cmds)
	}

	// results: only the leasing agent, valid status, before expiry
	id := first
	cases := map[string]struct {
		agent, id string
		body      any
		want      int
	}{
		"other agent":   {"b", id, protocol.CommandResult{Status: protocol.CommandSucceeded}, http.StatusNotFound},
		"bad status":    {"a", id, protocol.CommandResult{Status: "done"}, http.StatusBadRequest},
		"bad id":        {"a", "not-a-ulid", protocol.CommandResult{Status: protocol.CommandSucceeded}, http.StatusNotFound},
		"unknown field": {"c", other, `{"status":"succeeded","extra":1}`, http.StatusConflict}, // read, then refused as unleased
		"long error":    {"a", id, protocol.CommandResult{Status: protocol.CommandFailed, Error: strings.Repeat("e", maxResultError+1)}, http.StatusBadRequest},
		"unleased":      {"c", other, protocol.CommandResult{Status: protocol.CommandSucceeded}, http.StatusConflict},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if code := sh.do(http.MethodPost, "/agent/v1/commands/"+tc.id+"/result", sh.sessions[tc.agent], tc.body).Code; code != tc.want {
				t.Fatalf("status = %d, want %d", code, tc.want)
			}
		})
	}
	sh.advance(2 * time.Minute)
	if code := sh.result("a", id, protocol.CommandResult{Status: protocol.CommandSucceeded}); code != http.StatusConflict {
		t.Fatalf("result after expiry = %d, want 409", code)
	}
	if rec := sh.do(http.MethodGet, "/agent/v1/commands?wait=x", sh.sessions["a"], nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad wait = %d", rec.Code)
	}
}

func TestPlanKeySync_Renewal(t *testing.T) {
	reg, err := registry.Parse([]byte(`
issuers: [{name: local, url: "https://k8s.example.com", jwksFile: k.json}]
agents:
  - {id: a, cluster: a, region: use1, capabilities: [seal, renewal], identity: {k8s: {issuer: local, subject: "system:serviceaccount:a:agent"}}}
  - {id: b, cluster: b, region: use1, capabilities: [seal, renewal], identity: {k8s: {issuer: local, subject: "system:serviceaccount:b:agent"}}}
`), "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	st := func(id, renew string, ago time.Duration) store.AgentState {
		return store.AgentState{
			AgentID: id, LastCheckIn: now.Add(-ago),
			Capabilities: []string{protocol.CapabilitySeal, protocol.CapabilityRenewal},
			Commands:     []string{protocol.CommandRenewalEnable},
			Controller:   protocol.Controller{KeyRenewPeriod: renew, KeyOrderPriority: "CertNotBefore"},
			Keys:         []store.KeyRef{{Fingerprint: "SHA256:k", NotBefore: now.Add(-time.Hour)}},
		}
	}
	plan := func(self string, states map[string]store.AgentState, cmds []store.CommandRecord) bool {
		a, _ := reg.Agent(self)
		return planKeySync(fleet.Compute("dev", reg, states, fleet.Keys{}, now), a, states[self], false, cmds, fleet.Keys{}, now).EnableRenewal
	}

	off := map[string]store.AgentState{"a": st("a", "0s", 0), "b": st("b", "0s", 0)}
	if !plan("a", off, nil) || plan("b", off, nil) {
		t.Error("renewal should be asked of a (lowest ID) only")
	}
	// never on an agent's first check-in: one that starts beside others
	// checks in before their states are stored, and each could see itself
	// as the lowest
	a, _ := reg.Agent("a")
	if planKeySync(fleet.Compute("dev", reg, off, fleet.Keys{}, now), a, off["a"], true, nil, fleet.Keys{}, now).EnableRenewal {
		t.Error("renewal was asked on a's first check-in")
	}
	on := map[string]store.AgentState{"a": st("a", "0s", 0), "b": st("b", "720h0m0s", 0)}
	if plan("a", on, nil) || plan("b", on, nil) {
		t.Error("renewal is on in b; nothing to do")
	}
	// a is down: b takes over
	aDown := map[string]store.AgentState{"a": st("a", "0s", time.Hour), "b": st("b", "0s", 0)}
	if !plan("b", aDown, nil) {
		t.Error("b should be asked when a is down")
	}
	// an unknown period (deployment unreadable) is neither on nor a candidate
	unknown := map[string]store.AgentState{"a": st("a", "", 0), "b": st("b", "0s", 0)}
	if plan("a", unknown, nil) || !plan("b", unknown, nil) {
		t.Error("an agent that cannot read its period must not be the candidate")
	}
	// a recent failure holds off a retry
	finished := now.Add(-time.Minute)
	failed := []store.CommandRecord{{Type: protocol.CommandRenewalEnable, Status: store.CommandFailed, ExpiresAt: now.Add(time.Minute), FinishedAt: &finished}}
	if plan("a", off, failed) {
		t.Error("renewal retried right after a failure")
	}
	longAgo := now.Add(-retryAfterFailure - time.Minute)
	failed[0].FinishedAt = &longAgo
	if !plan("a", off, failed) {
		t.Error("renewal not retried after the hold")
	}
}
