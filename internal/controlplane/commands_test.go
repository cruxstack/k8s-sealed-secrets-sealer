package controlplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/agentauth"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/registry"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
)

// watchedStore is a memory store that watches, and can fail, command calls.
type watchedStore struct {
	*store.Memory

	mu sync.Mutex
	// fullReads counts reads of every command an agent has
	fullReads int
	// leases counts LeaseCommand calls; the failLease-th fails
	leases, failLease int
	// timeLeft is what the context of the last CommandsSince had left
	timeLeft time.Duration
}

func (w *watchedStore) Commands(ctx context.Context, agentID string) ([]store.CommandRecord, error) {
	w.mu.Lock()
	w.fullReads++
	w.mu.Unlock()
	return w.Memory.Commands(ctx, agentID)
}

func (w *watchedStore) CommandsSince(ctx context.Context, agentID string, since time.Time) ([]store.CommandRecord, error) {
	w.mu.Lock()
	w.timeLeft = 0
	if deadline, ok := ctx.Deadline(); ok {
		w.timeLeft = time.Until(deadline)
	}
	w.mu.Unlock()
	return w.Memory.CommandsSince(ctx, agentID, since)
}

func (w *watchedStore) LeaseCommand(ctx context.Context, agentID, id string, now time.Time) (bool, error) {
	w.mu.Lock()
	w.leases++
	fail := w.leases == w.failLease
	w.mu.Unlock()
	if fail {
		return false, errors.New("throttled")
	}
	return w.Memory.LeaseCommand(ctx, agentID, id, now)
}

// pollHarness is one agent, a, that may run every command.
type pollHarness struct {
	t     *testing.T
	srv   *Server
	h     http.Handler
	store *watchedStore
	token string
	logs  *bytes.Buffer
	agent *registry.Agent
	// entropy keeps IDs made in the same millisecond in order
	entropy *ulid.MonotonicEntropy
}

func newPollHarness(t *testing.T) *pollHarness {
	t.Helper()
	reg, err := registry.Parse([]byte(`
issuers: [{name: local, url: "https://k8s.example.com", jwksFile: k.json}]
agents:
  - {id: a, cluster: a, region: use1, capabilities: [seal, keys, renewal], identity: {k8s: {issuer: local, subject: "system:serviceaccount:a:agent"}}}
`), "")
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := agentauth.NewSessions([]byte("0123456789abcdef0123456789abcdef"), "https://sealer.dev.example.com", "dev", nil)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := sessions.Issue("a")
	if err != nil {
		t.Fatal(err)
	}
	ph := &pollHarness{
		t: t, store: &watchedStore{Memory: store.NewMemory()}, token: token, logs: &bytes.Buffer{},
		entropy: ulid.Monotonic(rand.Reader, 0),
	}
	ph.agent, _ = reg.Agent("a")
	ph.srv = New(Options{
		Logger:       slog.New(slog.NewTextHandler(ph.logs, nil)),
		Env:          "dev",
		Registry:     reg,
		Sessions:     sessions,
		Store:        ph.store,
		PollInterval: 10 * time.Millisecond,
	})
	ph.h = ph.srv.Handler()
	return ph
}

// queue queues a keys.restore.v1 for a, with a payload of about size bytes,
// made at made.
func (ph *pollHarness) queue(made time.Time, size int) string {
	ph.t.Helper()
	id := ulid.MustNew(ulid.Timestamp(made), ph.entropy).String()
	payload, _ := json.Marshal(protocol.KeysRestorePayload{Fingerprints: []string{strings.Repeat("f", size)}})
	now := time.Now().UTC()
	err := ph.store.PutCommand(context.Background(), store.CommandRecord{
		AgentID: "a", ID: id, Type: protocol.CommandKeysRestore, Status: store.CommandQueued,
		CreatedAt: now, ExpiresAt: now.Add(keyCommandTTL), Payload: string(payload),
	})
	if err != nil {
		ph.t.Fatal(err)
	}
	return id
}

// poll leases a's commands without waiting.
func (ph *pollHarness) poll() (int, []protocol.Command, int) {
	ph.t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/agent/v1/commands?wait=0", nil)
	req.Header.Set("Authorization", "Bearer "+ph.token)
	rec := httptest.NewRecorder()
	ph.h.ServeHTTP(rec, req)
	var resp protocol.CommandsResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return rec.Code, resp.Commands, rec.Body.Len()
}

func (ph *pollHarness) status(id string) string {
	ph.t.Helper()
	c, _, _ := ph.store.Command(context.Background(), "a", id)
	return c.Status
}

func TestCommands_PollReadsOnlyRecentCommands(t *testing.T) {
	ph := newPollHarness(t)
	// queued and unexpired, but made longer ago than any command lives
	stale := ph.queue(time.Now().Add(-commandLookback-time.Minute), 10)
	fresh := ph.queue(time.Now(), 10)

	code, cmds, _ := ph.poll()
	if code != http.StatusOK || len(cmds) != 1 || cmds[0].ID != fresh {
		t.Fatalf("poll = %d %+v", code, cmds)
	}
	if ph.status(stale) != store.CommandQueued {
		t.Errorf("a command older than the lookback was read")
	}
	if ph.store.fullReads != 0 {
		t.Errorf("the poll read every command %d times", ph.store.fullReads)
	}
}

func TestCommands_ChoosingASealerReadsOnlyRecentCommands(t *testing.T) {
	ph := newPollHarness(t)
	in := checkIn(protoKey(t, time.Now().Add(-time.Hour)))
	in.Commands = []string{protocol.CommandSeal}
	state, _, _, err := validateCheckIn(in, ph.agent, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := ph.store.PutAgentState(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	ph.queue(time.Now(), 10)

	agent, _, err := ph.srv.chooseSealer(context.Background(), nil, time.Now().UTC())
	if err != nil || agent.ID != "a" {
		t.Fatalf("chooseSealer = %+v, %v", agent, err)
	}
	if ph.store.fullReads != 0 {
		t.Errorf("choosing a sealer read every command %d times", ph.store.fullReads)
	}
}

func TestSealsRunning_ReadsOnlyOpenCommands(t *testing.T) {
	ph := newPollHarness(t)
	ctx := context.Background()
	now := time.Now().UTC()
	err := ph.store.PutCommand(ctx, store.CommandRecord{
		AgentID: "a", ID: ulid.Make().String(), Type: protocol.CommandSeal, Status: store.CommandQueued,
		CreatedAt: now, ExpiresAt: now.Add(sealCommandTTL), Payload: `{}`, SessionID: "S1",
	})
	if err != nil {
		t.Fatal(err)
	}
	for session, want := range map[string]bool{"S1": true, "S2": false} {
		if running, err := ph.srv.sealsRunning(ctx, session, now); err != nil || running != want {
			t.Errorf("sealsRunning(%s) = %v, %v; want %v", session, running, err, want)
		}
	}
	if ph.store.fullReads != 0 {
		t.Errorf("waiting for seals read every command %d times", ph.store.fullReads)
	}
}

// Key sync weighs key commands that finished up to retryAfterFailure after
// they expired. It reads those, and only those.
func TestKeySync_ReadsOnlyTheCommandsThatCount(t *testing.T) {
	ph := newPollHarness(t)
	ctx := context.Background()
	// a renewal.enable.v1 that ran its full time and failed 4 minutes ago
	// still holds off another
	made := time.Now().Add(-keyCommandTTL - 4*time.Minute).UTC()
	finished := made.Add(keyCommandTTL - time.Second)
	err := ph.store.PutCommand(ctx, store.CommandRecord{
		AgentID: "a", ID: ulid.MustNew(ulid.Timestamp(made), ph.entropy).String(), Type: protocol.CommandRenewalEnable,
		Status: store.CommandFailed, CreatedAt: made, ExpiresAt: made.Add(keyCommandTTL), FinishedAt: &finished, Payload: `{}`,
	})
	if err != nil {
		t.Fatal(err)
	}

	// a, the only cluster, renews no key and may turn renewal on
	in := checkIn(protoKey(t, time.Now().Add(-time.Hour)))
	in.Capabilities = []string{protocol.CapabilitySeal, protocol.CapabilityKeys, protocol.CapabilityRenewal}
	in.Commands = []string{protocol.CommandKeysRestore, protocol.CommandRenewalEnable}
	in.Controller.KeyRenewPeriod = "0"
	body, _ := json.Marshal(in)
	req := httptest.NewRequest(http.MethodPost, "/agent/v1/checkin", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+ph.token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	ph.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("check-in = %d %s", rec.Code, rec.Body)
	}

	all, _ := ph.store.Memory.Commands(ctx, "a")
	if len(all) != 1 {
		t.Fatalf("commands = %+v; the failed renewal.enable.v1 was not read, so another was queued", all)
	}
	if ph.store.fullReads != 0 {
		t.Errorf("key sync read every command %d times", ph.store.fullReads)
	}
}

func TestCommands_PollIsBoundedInCountAndSize(t *testing.T) {
	t.Run("count", func(t *testing.T) {
		ph := newPollHarness(t)
		for range maxPollCommands + 4 {
			ph.queue(time.Now(), 10)
		}
		if _, cmds, _ := ph.poll(); len(cmds) != maxPollCommands {
			t.Fatalf("first poll leased %d, want %d", len(cmds), maxPollCommands)
		}
		if _, cmds, _ := ph.poll(); len(cmds) != 4 {
			t.Fatalf("second poll leased %d, want the 4 left", len(cmds))
		}
	})
	t.Run("size", func(t *testing.T) {
		ph := newPollHarness(t)
		for range 8 {
			ph.queue(time.Now(), 100<<10)
		}
		_, cmds, size := ph.poll()
		if len(cmds) != maxPollBytes/(100<<10) || size > maxPollBytes {
			t.Fatalf("first poll leased %d in %d bytes, want %d within %d", len(cmds), size, maxPollBytes/(100<<10), maxPollBytes)
		}
		if _, rest, _ := ph.poll(); len(cmds)+len(rest) != 8 {
			t.Fatalf("second poll leased %d, want the %d left", len(rest), 8-len(cmds))
		}
	})
	t.Run("one command larger than the budget", func(t *testing.T) {
		ph := newPollHarness(t)
		ph.queue(time.Now(), maxPollBytes)
		if _, cmds, _ := ph.poll(); len(cmds) != 1 {
			t.Fatalf("poll leased %d; a command over the budget must still go out alone", len(cmds))
		}
	})
}

func TestCommands_PollSendsWhatItLeasedWhenALeaseFails(t *testing.T) {
	ph := newPollHarness(t)
	first := ph.queue(time.Now(), 10)
	second := ph.queue(time.Now(), 10)
	ph.store.failLease = 2

	code, cmds, _ := ph.poll()
	if code != http.StatusOK || len(cmds) != 1 || cmds[0].ID != first {
		t.Fatalf("poll = %d %+v, want the command leased before the failure", code, cmds)
	}
	if !strings.Contains(ph.logs.String(), "failed to lease commands") {
		t.Error("the failed lease was not logged")
	}
	if ph.status(second) != store.CommandQueued {
		t.Fatalf("second command = %s, want it still queued", ph.status(second))
	}
	// with nothing leased, a failure is an error
	ph.store.failLease = ph.store.leases + 1
	if code, _, _ := ph.poll(); code != http.StatusInternalServerError {
		t.Fatalf("poll with nothing leased = %d, want 500", code)
	}
	if _, cmds, _ := ph.poll(); len(cmds) != 1 || cmds[0].ID != second {
		t.Fatalf("next poll = %+v", cmds)
	}
}

func TestCommands_PollSkipsACommandItCannotSend(t *testing.T) {
	ph := newPollHarness(t)
	now := time.Now().UTC()
	broken := ulid.Make().String()
	// a secret goes into the payload, which must then be an object
	err := ph.store.PutCommand(context.Background(), store.CommandRecord{
		AgentID: "a", ID: broken, Type: protocol.CommandSeal, Status: store.CommandQueued,
		CreatedAt: now, ExpiresAt: now.Add(time.Minute), Payload: `[]`, Secret: `{}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	good := ph.queue(time.Now(), 10)

	code, cmds, _ := ph.poll()
	if code != http.StatusOK || len(cmds) != 1 || cmds[0].ID != good {
		t.Fatalf("poll = %d %+v", code, cmds)
	}
	if ph.status(broken) != store.CommandQueued || !strings.Contains(ph.logs.String(), "failed to prepare command") {
		t.Fatalf("broken command = %s; logs: %s", ph.status(broken), ph.logs)
	}
}

func TestCommands_PollHasADeadline(t *testing.T) {
	ph := newPollHarness(t)
	if code, _, _ := ph.poll(); code != http.StatusOK {
		t.Fatalf("poll = %d", code)
	}
	if left := ph.store.timeLeft; left <= 0 || left > pollTimeout {
		t.Fatalf("the poll's store calls had %v left, want a deadline within %v", left, pollTimeout)
	}
}

func TestCommands_NoLeaseWithoutTimeToRespond(t *testing.T) {
	ph := newPollHarness(t)
	id := ph.queue(time.Now(), 10)
	ctx, cancel := context.WithTimeout(context.Background(), leaseMargin/2)
	defer cancel()
	cmds, err := ph.srv.leaseCommands(ctx, ph.agent)
	if err != nil || len(cmds) != 0 {
		t.Fatalf("leaseCommands = %+v, %v; want nothing leased", cmds, err)
	}
	if ph.status(id) != store.CommandQueued {
		t.Fatalf("command = %s, want it still queued", ph.status(id))
	}
	if cmds, err := ph.srv.leaseCommands(context.Background(), ph.agent); err != nil || len(cmds) != 1 {
		t.Fatalf("leaseCommands with time = %+v, %v", cmds, err)
	}
}
