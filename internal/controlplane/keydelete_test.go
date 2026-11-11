package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/fleet"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/registry"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
)

// cleanupRegistry is an env whose agents a and b count key references and
// remove deleted keys; c has keys but not cleanup.
const cleanupRegistry = `
issuers: [{name: local, url: "https://k8s.example.com", jwksFile: k.json}]
agents:
  - {id: a, cluster: a, region: use1, capabilities: [seal, keys, cleanup], identity: {k8s: {issuer: local, subject: "system:serviceaccount:a:agent"}}}
  - {id: b, cluster: b, region: use1, capabilities: [seal, keys, cleanup], identity: {k8s: {issuer: local, subject: "system:serviceaccount:b:agent"}}}
  - {id: c, cluster: c, region: use2, capabilities: [seal, keys], identity: {k8s: {issuer: local, subject: "system:serviceaccount:c:agent"}}}
`

// counts is a key usage report: values per key, one SealedSecret per key.
func counts(scanned time.Time, perKey map[string]int) *protocol.KeyUsage {
	u := &protocol.KeyUsage{ScannedAt: scanned, Namespaces: []string{"apps", "sealed-secrets"}}
	for fp, n := range perKey {
		if u.Keys == nil {
			u.Keys = map[string]protocol.KeyUse{}
		}
		u.Keys[fp] = protocol.KeyUse{Values: n, SealedSecrets: 1}
		u.Values += n
		u.SealedSecrets++
	}
	return u
}

// cleanupCheckIn checks in as a (or b) with seal, keys and cleanup, as c
// with seal and keys, carrying usage.
func (kh *keyHarness) cleanupCheckIn(id string, usage *protocol.KeyUsage, ks ...testKey) protocol.CheckInResponse {
	kh.t.Helper()
	rec := kh.cleanupCheckInRaw(id, usage, ks...)
	if rec.Code != http.StatusOK {
		kh.t.Fatalf("check-in %s = %d %s", id, rec.Code, rec.Body)
	}
	return decode[protocol.CheckInResponse](kh.t, rec)
}

func (kh *keyHarness) cleanupCheckInRaw(id string, usage *protocol.KeyUsage, ks ...testKey) *httptest.ResponseRecorder {
	kh.t.Helper()
	in := checkIn(protoKeys(ks)...)
	in.Controller.KeyRenewPeriod = "0s"
	in.Capabilities = []string{protocol.CapabilitySeal, protocol.CapabilityKeys}
	in.Commands = []string{protocol.CommandKeysRestore}
	if id != "c" {
		in.Capabilities = append(in.Capabilities, protocol.CapabilityCleanup)
		in.Commands = append(in.Commands, protocol.CommandKeysDelete)
	}
	in.KeyUsage = usage
	return kh.do(http.MethodPost, "/agent/v1/checkin", kh.sessions[id], in)
}

func (kh *keyHarness) deleteKey(fp string) *httptest.ResponseRecorder {
	kh.t.Helper()
	return kh.userDo("alice", http.MethodPost, "/api/v1/keys/"+protocol.FingerprintPath(fp)+"/delete", true)
}

// errorOf is an error response's message.
func errorOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	return decode[protocol.Error](t, rec).Error
}

// TestKeyDelete_FromRevocationToRemoval walks a key from active to deleted
// and removed from every cluster: the gate refuses until every cluster has
// counted no value sealed with it since it was revoked, and agents then
// remove it, one command at a time.
func TestKeyDelete_FromRevocationToRemoval(t *testing.T) {
	kh := newKeyHarnessWith(t, cleanupRegistry)
	old := newTestKey(t, time.Now().Add(-48*time.Hour))
	env := newTestKey(t, time.Now().Add(-time.Hour))
	scan := func() time.Time { return kh.clock().Add(-time.Second) }
	kh.cleanupCheckIn("a", counts(scan(), map[string]int{env.Fingerprint: 2}), old, env)
	kh.cleanupCheckIn("b", counts(scan(), map[string]int{env.Fingerprint: 1}), old, env)
	for _, k := range []testKey{old, env} {
		if code := kh.upload("a", k); code != http.StatusOK {
			t.Fatalf("upload = %d", code)
		}
	}

	// an active key is not deleted
	if rec := kh.deleteKey(old.Fingerprint); rec.Code != http.StatusConflict || errorOf(t, rec) != refuseDeleteActive {
		t.Fatalf("delete of an active key = %d %s", rec.Code, rec.Body)
	}
	k := fleetKey(t, kh.fleet(), old.Fingerprint)
	if k.References.Values != 0 || len(k.References.Clusters) != 2 || k.Deletable || k.DeleteBlocked != refuseDeleteActive {
		t.Fatalf("active key in the fleet = %+v", k)
	}
	if refs := fleetKey(t, kh.fleet(), env.Fingerprint).References; refs.Values != 3 || refs.SealedSecrets != 2 {
		t.Fatalf("env key's references = %+v", refs)
	}

	// revoked: the counts came in before, so they do not count yet
	kh.advance(time.Minute)
	if rec := kh.setStatus(old.Fingerprint, "revoke"); rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d", rec.Code)
	}
	waiting := "Waiting for a and b to count the values sealed with it since it was revoked; clusters count every few minutes."
	if rec := kh.deleteKey(old.Fingerprint); rec.Code != http.StatusConflict || errorOf(t, rec) != waiting {
		t.Fatalf("delete before a count = %d %s", rec.Code, rec.Body)
	}
	if k := fleetKey(t, kh.fleet(), old.Fingerprint); k.Deletable || k.DeleteBlocked != waiting {
		t.Fatalf("revoked key in the fleet = deletable %v, %q", k.Deletable, k.DeleteBlocked)
	}

	// a's cluster has a value sealed with it
	kh.advance(time.Minute)
	kh.cleanupCheckIn("a", counts(scan(), map[string]int{old.Fingerprint: 1, env.Fingerprint: 2}), old, env)
	kh.cleanupCheckIn("b", counts(scan(), map[string]int{env.Fingerprint: 1}), old, env)
	inUse := "1 value in 1 SealedSecret uses it (a)."
	if rec := kh.deleteKey(old.Fingerprint); rec.Code != http.StatusConflict || errorOf(t, rec) != inUse {
		t.Fatalf("delete of a key in use = %d %s", rec.Code, rec.Body)
	}

	// once that value is sealed again, the key goes
	kh.advance(time.Minute)
	kh.cleanupCheckIn("a", counts(scan(), map[string]int{env.Fingerprint: 3}), old, env)
	rec := kh.deleteKey(old.Fingerprint)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body)
	}
	v := decode[keyStatusView](t, rec)
	if v.Status != store.KeyDeleted || v.StatusBy != "alice" || v.PurgeAt == nil || !v.PurgeAt.Equal(kh.clock().Add(deletedKeyRetention)) {
		t.Fatalf("deleted = %+v", v)
	}
	if !strings.Contains(kh.logs.String(), "event=key.deleted") || !strings.Contains(kh.logs.String(), "user=alice") {
		t.Error("key.deleted was not logged with the admin")
	}
	if rec := kh.deleteKey(old.Fingerprint); rec.Code != http.StatusConflict || errorOf(t, rec) != refuseDeleteDeleted {
		t.Fatalf("delete again = %d %s", rec.Code, rec.Body)
	}
	if rec := kh.setStatus(old.Fingerprint, "revoke"); rec.Code != http.StatusConflict || errorOf(t, rec) != refuseRevokeDeleted {
		t.Fatalf("revoke of a deleted key = %d %s", rec.Code, rec.Body)
	}
	k = fleetKey(t, kh.fleet(), old.Fingerprint)
	if k.Status != store.KeyDeleted || k.DeletedBy != "alice" || k.RevokedBy != adminTokenActor || k.PurgeAt == nil || k.Purged || len(k.Holders) != 2 ||
		k.Deletable || k.DeleteBlocked != refuseDeleteDeleted {
		t.Fatalf("deleted key in the fleet = %+v", k)
	}
	// it is never restored, escrowed or handed out again
	if rec := kh.download("b", old.Fingerprint); rec.Code != http.StatusGone {
		t.Fatalf("download of a deleted key = %d", rec.Code)
	}
	if code := kh.upload("b", old); code != http.StatusConflict {
		t.Fatalf("upload of a deleted key = %d", code)
	}

	// a removes it at its next check-in
	kh.cleanupCheckIn("a", counts(scan(), map[string]int{env.Fingerprint: 3}), old, env)
	cmds := kh.poll("a")
	if len(cmds) != 1 || cmds[0].Type != protocol.CommandKeysDelete {
		t.Fatalf("a commands = %+v", cmds)
	}
	var p protocol.KeysDeletePayload
	if err := json.Unmarshal(cmds[0].Payload, &p); err != nil || !slices.Equal(p.Fingerprints, []string{old.Fingerprint}) {
		t.Fatalf("delete payload = %s", cmds[0].Payload)
	}
	res, _ := json.Marshal(protocol.KeysDeleteResult{Keys: []protocol.KeyDeletion{{Fingerprint: old.Fingerprint, Outcome: protocol.KeyRemoved}}, ControllerRestarted: true})
	if code := kh.result("a", cmds[0].ID, protocol.CommandResult{Status: protocol.CommandSucceeded, Result: res}); code != http.StatusOK {
		t.Fatalf("delete result = %d", code)
	}
	if !strings.Contains(kh.logs.String(), "event=key.removed") {
		t.Error("key.removed was not logged")
	}
	// a check-in that still predates the removal does not ask again
	kh.cleanupCheckIn("a", counts(scan(), map[string]int{env.Fingerprint: 3}), old, env)
	if cmds := kh.poll("a"); len(cmds) != 0 {
		t.Fatalf("removal asked again before it settled: %+v", cmds)
	}
	kh.cleanupCheckIn("a", counts(scan(), map[string]int{env.Fingerprint: 3}), env)

	// b refuses: a value sealed with it showed up since
	kh.cleanupCheckIn("b", counts(scan(), map[string]int{env.Fingerprint: 1}), old, env)
	cmds = kh.poll("b")
	if len(cmds) != 1 || cmds[0].Type != protocol.CommandKeysDelete {
		t.Fatalf("b commands = %+v", cmds)
	}
	refusal := protocol.KeyDeletion{Fingerprint: old.Fingerprint, Outcome: protocol.KeyRefused,
		Reason: "1 value in 1 SealedSecret is sealed with it", Values: 1, SealedSecrets: 1}
	res, _ = json.Marshal(protocol.KeysDeleteResult{Keys: []protocol.KeyDeletion{refusal}})
	if code := kh.result("b", cmds[0].ID, protocol.CommandResult{Status: protocol.CommandFailed, Error: "refused to remove 1 of 1 keys", Result: res}); code != http.StatusOK {
		t.Fatalf("refused result = %d", code)
	}
	if !strings.Contains(kh.logs.String(), "event=key.remove_refused") {
		t.Error("key.remove_refused was not logged")
	}
	f := kh.fleet()
	if issues := fleetAgent(t, f, "b").Issues; !slices.Contains(issues, "refused to remove deleted key "+old.Fingerprint+": "+refusal.Reason) {
		t.Fatalf("b's issues = %q", issues)
	}
	if k := fleetKey(t, f, old.Fingerprint); !slices.Equal(k.Holders, []string{"b"}) {
		t.Fatalf("holders of the deleted key = %v", k.Holders)
	}
	// a refusal usually lasts: the removal is asked again only later
	kh.advance(removeRetryAfterFailure - time.Minute)
	kh.cleanupCheckIn("b", counts(scan(), map[string]int{env.Fingerprint: 1}), old, env)
	if cmds := kh.poll("b"); len(cmds) != 0 {
		t.Fatalf("removal asked again right after a refusal: %+v", cmds)
	}
	kh.advance(2 * time.Minute)
	kh.cleanupCheckIn("b", counts(scan(), map[string]int{env.Fingerprint: 1}), old, env)
	if cmds := kh.poll("b"); len(cmds) != 1 || cmds[0].Type != protocol.CommandKeysDelete {
		t.Fatalf("b commands after the hold = %+v", cmds)
	}

	// reinstated: active again, and restored where it was removed
	rec = kh.setStatus(old.Fingerprint, "reinstate")
	if v := decode[keyStatusView](t, rec); rec.Code != http.StatusOK || v.Status != store.KeyActive || v.PurgeAt != nil {
		t.Fatalf("reinstate = %d %+v", rec.Code, v)
	}
	if k := fleetKey(t, kh.fleet(), old.Fingerprint); k.Status != store.KeyActive || k.DeletedBy != "" || k.RevokedBy != "" {
		t.Fatalf("reinstated key in the fleet = %+v", k)
	}
	kh.cleanupCheckIn("a", counts(scan(), map[string]int{env.Fingerprint: 3}), env)
	cmds = kh.poll("a")
	if len(cmds) != 1 || cmds[0].Type != protocol.CommandKeysRestore || !strings.Contains(string(cmds[0].Payload), old.Fingerprint) {
		t.Fatalf("a commands after reinstating = %+v", cmds)
	}
	if rec := kh.download("a", old.Fingerprint); rec.Code != http.StatusOK {
		t.Fatalf("download of a reinstated key = %d", rec.Code)
	}
}

// A deleted key every cluster removed comes back to every cluster when it
// is reinstated, from escrow: restores otherwise spread only keys some
// cluster holds.
func TestKeyDelete_ReinstatedKeyHeldByNoneIsRestored(t *testing.T) {
	kh := newKeyHarnessWith(t, cleanupRegistry)
	old := newTestKey(t, time.Now().Add(-48*time.Hour))
	env := newTestKey(t, time.Now().Add(-time.Hour))
	for _, id := range []string{"a", "b"} {
		kh.cleanupCheckIn(id, nil, old, env)
	}
	for _, k := range []testKey{old, env} {
		if code := kh.upload("a", k); code != http.StatusOK {
			t.Fatalf("upload = %d", code)
		}
	}
	if rec := kh.setStatus(old.Fingerprint, "revoke"); rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d", rec.Code)
	}
	kh.advance(time.Minute)
	for _, id := range []string{"a", "b"} {
		kh.cleanupCheckIn(id, counts(kh.clock(), map[string]int{env.Fingerprint: 1}), old, env)
	}
	if rec := kh.deleteKey(old.Fingerprint); rec.Code != http.StatusOK {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body)
	}
	// both clusters remove it
	for _, id := range []string{"a", "b"} {
		kh.cleanupCheckIn(id, counts(kh.clock(), map[string]int{env.Fingerprint: 1}), old, env)
		if cmds := kh.poll(id); len(cmds) != 1 || cmds[0].Type != protocol.CommandKeysDelete {
			t.Fatalf("%s commands = %+v", id, cmds)
		}
		kh.cleanupCheckIn(id, counts(kh.clock(), map[string]int{env.Fingerprint: 1}), env)
	}
	// held by none, its escrowed copy is still there to reinstate it from,
	// and the fleet says so
	if k := fleetKey(t, kh.fleet(), old.Fingerprint); len(k.Holders) != 0 || k.EscrowCopies != 1 {
		t.Fatalf("after the removals: holders %v, escrow copies %d", k.Holders, k.EscrowCopies)
	}

	// a restore found it present in b before it was deleted, which would
	// hold it off for an hour; that says nothing once it is reinstated
	finished := kh.clock().Add(-time.Minute)
	payload, _ := json.Marshal(protocol.KeysRestorePayload{Fingerprints: []string{old.Fingerprint}})
	found, _ := json.Marshal(protocol.KeysRestoreResult{Restored: []string{}, AlreadyPresent: []string{old.Fingerprint}, Failed: []protocol.KeyFailure{}})
	if err := kh.store.PutCommand(context.Background(), store.CommandRecord{
		AgentID: "b", ID: ulid.Make().String(), Type: protocol.CommandKeysRestore, Status: store.CommandSucceeded,
		CreatedAt: finished, ExpiresAt: finished.Add(keyCommandTTL), FinishedAt: &finished, Payload: string(payload), Result: string(found),
	}); err != nil {
		t.Fatal(err)
	}
	kh.advance(settleAfterSuccess)

	if rec := kh.setStatus(old.Fingerprint, "reinstate"); rec.Code != http.StatusOK {
		t.Fatalf("reinstate = %d", rec.Code)
	}
	if k := fleetKey(t, kh.fleet(), old.Fingerprint); k.Status != store.KeyActive || len(k.Holders) != 0 {
		t.Fatalf("reinstated key = %+v", k)
	}
	for _, id := range []string{"a", "b"} {
		kh.cleanupCheckIn(id, counts(kh.clock(), map[string]int{env.Fingerprint: 1}), env)
		cmds := kh.poll(id)
		if len(cmds) != 1 || cmds[0].Type != protocol.CommandKeysRestore || !strings.Contains(string(cmds[0].Payload), old.Fingerprint) {
			t.Fatalf("%s commands after reinstating = %+v", id, cmds)
		}
	}
}

// After its escrowed copies are purged, a deleted key cannot come back,
// and once no cluster holds it, it leaves the fleet view.
func TestKeyDelete_PurgedKeyCannotBeReinstated(t *testing.T) {
	kh := newKeyHarnessWith(t, cleanupRegistry)
	old := newTestKey(t, time.Now().Add(-48*time.Hour))
	env := newTestKey(t, time.Now().Add(-time.Hour))
	kh.cleanupCheckIn("a", nil, old, env)
	if code := kh.upload("a", old); code != http.StatusOK {
		t.Fatalf("upload = %d", code)
	}
	if rec := kh.setStatus(old.Fingerprint, "revoke"); rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d", rec.Code)
	}
	kh.advance(time.Minute)
	kh.cleanupCheckIn("a", counts(kh.clock(), map[string]int{env.Fingerprint: 1}), old, env)
	// the admin token deletes it where the env allows it
	rec := kh.setStatus(old.Fingerprint, "delete")
	if v := decode[keyStatusView](t, rec); rec.Code != http.StatusOK || v.StatusBy != adminTokenActor {
		t.Fatalf("delete with the admin token = %d %+v", rec.Code, v)
	}

	kh.advance(deletedKeyRetention)
	if rec := kh.setStatus(old.Fingerprint, "reinstate"); rec.Code != http.StatusConflict || errorOf(t, rec) != refuseReinstatePurged {
		t.Fatalf("reinstate after the purge = %d %s", rec.Code, rec.Body)
	}
	// a still holds it, so it is listed, purged
	kh.cleanupCheckIn("a", counts(kh.clock(), map[string]int{env.Fingerprint: 1}), old, env)
	if k := fleetKey(t, kh.fleet(), old.Fingerprint); k.Status != store.KeyDeleted || !k.Purged || k.EscrowCopies != 0 {
		t.Fatalf("purged key a holds = %+v", k)
	}
	kh.cleanupCheckIn("a", counts(kh.clock(), map[string]int{env.Fingerprint: 1}), env)
	if _, listed := kh.fleet().Key(old.Fingerprint); listed {
		t.Fatal("a purged key no cluster holds is listed")
	}
}

// A cluster whose agent cannot count references holds every deletion back.
func TestKeyDelete_NeedsEveryClusterToCount(t *testing.T) {
	kh := newKeyHarnessWith(t, cleanupRegistry)
	old := newTestKey(t, time.Now().Add(-48*time.Hour))
	env := newTestKey(t, time.Now().Add(-time.Hour))
	kh.cleanupCheckIn("c", nil, old, env)
	if rec := kh.setStatus(old.Fingerprint, "revoke"); rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d", rec.Code)
	}
	kh.advance(time.Minute)
	kh.cleanupCheckIn("a", counts(kh.clock(), nil), old, env)
	want := "c cannot count the values sealed with it: it needs the cleanup capability."
	if rec := kh.deleteKey(old.Fingerprint); rec.Code != http.StatusConflict || errorOf(t, rec) != want {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body)
	}
	k := fleetKey(t, kh.fleet(), old.Fingerprint)
	if !slices.Equal(k.References.Uncounted, []string{"c"}) || len(k.References.Clusters) != 1 {
		t.Fatalf("references = %+v", k.References)
	}
	// c is never sent a removal
	if cmds := kh.poll("c"); slices.ContainsFunc(cmds, func(c protocol.Command) bool { return c.Type == protocol.CommandKeysDelete }) {
		t.Fatalf("c commands = %+v", cmds)
	}
}

func TestCheckIn_KeyUsage(t *testing.T) {
	kh := newKeyHarnessWith(t, cleanupRegistry)
	k := newTestKey(t, time.Now().Add(-time.Hour))
	scanned := kh.clock().Add(-time.Second)
	first := kh.clock()
	report := counts(scanned, map[string]int{k.Fingerprint: 2})
	report.Unmatched, report.Values = 1, 3
	kh.cleanupCheckIn("a", report, k)

	// the same report again keeps the time it first came in
	kh.advance(time.Minute)
	kh.cleanupCheckIn("a", report, k)
	f := kh.fleet()
	a := fleetAgent(t, f, "a")
	if u := a.KeyUsage; u == nil || !u.CountedAt.Equal(first) || u.Values != 3 || u.Unmatched != 1 || len(u.Namespaces) != 2 {
		t.Fatalf("a's usage = %+v", a.KeyUsage)
	}
	if !slices.Contains(a.Issues, "1 value in this cluster's SealedSecrets matches none of its keys: the controller cannot decrypt them") {
		t.Fatalf("a's issues = %q", a.Issues)
	}
	// key.unmatched_values is logged once, when the condition first shows
	unmatched := func() int { return strings.Count(kh.logs.String(), "event=key.unmatched_values") }
	if n := unmatched(); n != 1 {
		t.Fatalf("key.unmatched_values logged %d times, want 1", n)
	}
	kh.advance(time.Minute)
	more := counts(kh.clock(), map[string]int{k.Fingerprint: 2})
	more.Unmatched, more.Values = 2, 4
	kh.cleanupCheckIn("a", more, k)
	kh.cleanupCheckIn("a", counts(kh.clock().Add(time.Second), map[string]int{k.Fingerprint: 2}), k)
	kh.advance(time.Minute)
	more.ScannedAt = kh.clock()
	kh.cleanupCheckIn("a", more, k)
	if n := unmatched(); n != 2 {
		t.Fatalf("key.unmatched_values logged %d times, want 2: once more after it cleared", n)
	}

	// c has no cleanup capability: what it sends is not kept
	kh.cleanupCheckIn("c", counts(kh.clock(), nil), k)
	if u := fleetAgent(t, kh.fleet(), "c").KeyUsage; u != nil {
		t.Fatalf("c's usage = %+v", u)
	}

	// a report that cannot be stored is stored with a later check-in; the
	// check-in goes on
	kh.faulty.failUsageWrites.Store(true)
	next := kh.clock().Add(time.Minute)
	kh.advance(time.Minute)
	kh.cleanupCheckIn("a", counts(next, nil), k)
	kh.faulty.failUsageWrites.Store(false)
	kh.advance(time.Minute)
	kh.cleanupCheckIn("a", counts(next, nil), k)
	if u := fleetAgent(t, kh.fleet(), "a").KeyUsage; u == nil || u.Values != 0 || !u.CountedAt.Equal(kh.clock()) {
		t.Fatalf("a's usage after a failed write = %+v", u)
	}

	// a failed count is shown, and named in the agent's issues
	kh.cleanupCheckIn("a", &protocol.KeyUsage{ScannedAt: kh.clock(), Error: "failed to list SealedSecrets: forbidden"}, k)
	a = fleetAgent(t, kh.fleet(), "a")
	if a.KeyUsage == nil || a.KeyUsage.Error == "" || !slices.ContainsFunc(a.Issues, func(s string) bool { return strings.Contains(s, "forbidden") }) {
		t.Fatalf("a after a failed count = %+v, issues %q", a.KeyUsage, a.Issues)
	}
}

func TestCheckIn_RejectsInvalidKeyUsage(t *testing.T) {
	kh := newKeyHarnessWith(t, cleanupRegistry)
	k := newTestKey(t, time.Now().Add(-time.Hour))
	now := time.Now()
	many := &protocol.KeyUsage{ScannedAt: now, Values: protocol.MaxKeys + 1, SealedSecrets: protocol.MaxKeys + 1, Keys: map[string]protocol.KeyUse{}}
	for i := range protocol.MaxKeys + 1 {
		many.Keys[fmt.Sprintf("SHA256:k%d", i)] = protocol.KeyUse{Values: 1, SealedSecrets: 1}
	}
	cases := map[string]*protocol.KeyUsage{
		"no scan time":       {Values: 1},
		"negative count":     {ScannedAt: now, Values: -1},
		"unmatched too high": {ScannedAt: now, Values: 1, Unmatched: 2},
		"bad namespace":      {ScannedAt: now, Namespaces: []string{"Not_A_Namespace"}},
		"bad fingerprint":    {ScannedAt: now, Values: 1, SealedSecrets: 1, Keys: map[string]protocol.KeyUse{"md5:x": {Values: 1, SealedSecrets: 1}}},
		"key count too high": {ScannedAt: now, Values: 1, SealedSecrets: 1, Keys: map[string]protocol.KeyUse{"SHA256:x": {Values: 2, SealedSecrets: 1}}},
		"long error":         {ScannedAt: now, Error: strings.Repeat("e", protocol.MaxUsageError+1)},
		"too many keys":      many,
	}
	for name, u := range cases {
		t.Run(name, func(t *testing.T) {
			if rec := kh.cleanupCheckInRaw("a", u, k); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "key_usage") {
				t.Fatalf("check-in = %d %s", rec.Code, rec.Body)
			}
		})
	}
}

// A removal goes out one command at a time, to agents that can run it.
func TestPlanKeySync_Removal(t *testing.T) {
	reg, err := registry.Parse([]byte(cleanupRegistry), "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	gone := store.KeyRef{Fingerprint: "SHA256:gone", NotBefore: now.Add(-48 * time.Hour)}
	kept := store.KeyRef{Fingerprint: "SHA256:kept", NotBefore: now.Add(-time.Hour)}
	revoked := store.KeyRef{Fingerprint: "SHA256:revoked", NotBefore: now.Add(-24 * time.Hour)}
	keys := fleet.Keys{Revoked: map[string]store.RevokedKey{
		gone.Fingerprint:    {Fingerprint: gone.Fingerprint, Status: store.KeyDeleted},
		revoked.Fingerprint: {Fingerprint: revoked.Fingerprint},
	}}
	st := func(caps []string, commands ...string) store.AgentState {
		return store.AgentState{
			AgentID: "a", LastCheckIn: now, KeysComplete: true, Capabilities: caps, Commands: commands,
			Controller: protocol.Controller{KeyRenewPeriod: "0s", KeyOrderPriority: "CertNotBefore"},
			Keys:       []store.KeyRef{gone, revoked, kept},
		}
	}
	full := st([]string{protocol.CapabilitySeal, protocol.CapabilityKeys, protocol.CapabilityCleanup}, protocol.CommandKeysRestore, protocol.CommandKeysDelete)
	a, _ := reg.Agent("a")
	c, _ := reg.Agent("c")
	plan := func(self *registry.Agent, state store.AgentState, commands ...store.CommandRecord) []string {
		t.Helper()
		states := map[string]store.AgentState{self.ID: state}
		return planKeySync(fleet.Compute("dev", reg, states, keys, now), self, state, false, commands, keys, now).Remove
	}

	// only deleted keys, not those only revoked
	if got := plan(a, full); !slices.Equal(got, []string{gone.Fingerprint}) {
		t.Fatalf("remove = %v", got)
	}
	// not without the capability or the command
	if got := plan(a, st([]string{protocol.CapabilitySeal, protocol.CapabilityKeys}, protocol.CommandKeysRestore, protocol.CommandKeysDelete)); len(got) != 0 {
		t.Fatalf("remove without cleanup = %v", got)
	}
	if got := plan(a, st(full.Capabilities, protocol.CommandKeysRestore)); len(got) != 0 {
		t.Fatalf("remove without keys.delete.v1 = %v", got)
	}
	if got := plan(c, full); len(got) != 0 {
		t.Fatalf("remove for an agent not registered for cleanup = %v", got)
	}

	cmd := store.CommandRecord{
		AgentID: "a", ID: ulid.Make().String(), Type: protocol.CommandKeysDelete, Status: store.CommandLeased,
		CreatedAt: now, ExpiresAt: now.Add(keyCommandTTL),
	}
	finished := func(status string, ago time.Duration) store.CommandRecord {
		c := cmd
		at := now.Add(-ago)
		c.Status, c.FinishedAt = status, &at
		return c
	}
	expired := cmd
	expired.ExpiresAt = now.Add(-time.Second)
	for name, tc := range map[string]struct {
		cmd  store.CommandRecord
		want bool
	}{
		"open":                    {cmd, false},
		"succeeded just now":      {finished(store.CommandSucceeded, time.Minute), false},
		"succeeded and settled":   {finished(store.CommandSucceeded, settleAfterSuccess+time.Second), true},
		"refused just now":        {finished(store.CommandFailed, removeRetryAfterFailure-time.Second), false},
		"refused a while ago":     {finished(store.CommandFailed, removeRetryAfterFailure+time.Second), true},
		"expired without results": {expired, true},
	} {
		if got := len(plan(a, full, tc.cmd)) > 0; got != tc.want {
			t.Errorf("%s: removal queued = %v, want %v", name, got, tc.want)
		}
	}
	// a restore in flight does not hold a removal back
	restore := cmd
	restore.Type = protocol.CommandKeysRestore
	if got := plan(a, full, restore); len(got) != 1 {
		t.Errorf("remove beside an open restore = %v", got)
	}
}
