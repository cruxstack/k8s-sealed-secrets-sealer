package agent

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/testutil/testcerts"
)

type fakeInventory struct {
	report Report
	err    error
}

func (f *fakeInventory) Collect(context.Context) (Report, error) { return f.report, f.err }

type fakeControlPlane struct {
	mu     sync.Mutex
	got    []protocol.CheckIn
	errs   []error
	escrow []string
}

func (f *fakeControlPlane) CheckIn(_ context.Context, in protocol.CheckIn) (*protocol.CheckInResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, in)
	if len(f.errs) > 0 {
		err := f.errs[0]
		f.errs = f.errs[1:]
		if err != nil {
			return nil, err
		}
	}
	return &protocol.CheckInResponse{NextCheckInSeconds: 15, EscrowNeeded: f.escrow}, nil
}

type recordingEscrow struct{ got [][]string }

func (r *recordingEscrow) Escrow(_ context.Context, fps []string) { r.got = append(r.got, fps) }

func reportWith(t *testing.T) Report {
	t.Helper()
	k, err := toProtocolKey(testcerts.SelfSigned(t, testcerts.RSA(t, 2048), time.Now().Add(-time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	return Report{
		Controller: protocol.Controller{Namespace: "sealed-secrets", Name: "sealed-secrets-controller", ActiveFingerprint: k.Fingerprint},
		Keys:       []protocol.Key{k},
		Complete:   true,
	}
}

func newTestAgent(inv Collector, cp CheckInClient, now func() time.Time) (*Agent, *bytes.Buffer) {
	var logs bytes.Buffer
	return New(Options{
		Inventory:    inv,
		ControlPlane: cp,
		Interval:     15 * time.Second,
		Capabilities: []string{"seal", "keys"},
		Logger:       slog.New(slog.NewTextHandler(&logs, nil)),
		Version:      "test",
		Now:          now,
	}), &logs
}

func probe(t *testing.T, a *Agent, path string) int {
	t.Helper()
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code
}

func TestAgent_ChecksInWithReport(t *testing.T) {
	cp := &fakeControlPlane{}
	report := reportWith(t)
	a, logs := newTestAgent(&fakeInventory{report: report}, cp, nil)

	a.cycle(context.Background())
	if len(cp.got) != 1 {
		t.Fatalf("check-ins = %d", len(cp.got))
	}
	in := cp.got[0]
	if in.Protocol != protocol.Version || in.AgentVersion != "test" || !in.KeysComplete ||
		in.Controller.ActiveFingerprint != report.Controller.ActiveFingerprint || len(in.Capabilities) != 2 {
		t.Fatalf("check-in = %+v", in)
	}
	if in.Commands == nil {
		t.Error("commands must be an empty list, not null")
	}
	for _, ev := range []string{"event=controller.key_active", "event=agent.checked_in"} {
		if !strings.Contains(logs.String(), ev) {
			t.Errorf("missing %s in logs:\n%s", ev, logs)
		}
	}
}

func TestAgent_ReadinessFollowsCheckIns(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	cp := &fakeControlPlane{errs: []error{errors.New("down"), nil}}
	a, logs := newTestAgent(&fakeInventory{report: reportWith(t)}, cp, clock)

	if probe(t, a, "/healthz") != http.StatusOK {
		t.Fatal("/healthz must always answer")
	}
	a.cycle(context.Background())
	if probe(t, a, "/readyz") != http.StatusServiceUnavailable {
		t.Fatal("ready before any successful check-in")
	}
	if !strings.Contains(logs.String(), "event=agent.checkin_failed") {
		t.Error("failed check-in not logged")
	}
	a.cycle(context.Background())
	if probe(t, a, "/readyz") != http.StatusOK {
		t.Fatal("not ready after a successful check-in")
	}
	now = now.Add(time.Minute)
	if probe(t, a, "/readyz") != http.StatusServiceUnavailable {
		t.Fatal("still ready a minute after the last check-in")
	}
}

func TestAgent_SkipsCheckInWhenControllerUnreadable(t *testing.T) {
	cp := &fakeControlPlane{}
	a, logs := newTestAgent(&fakeInventory{err: errors.New("controller down")}, cp, nil)
	a.cycle(context.Background())
	if len(cp.got) != 0 {
		t.Fatal("checked in without a controller report")
	}
	if !strings.Contains(logs.String(), "event=controller.read_failed") {
		t.Error("controller failure not logged")
	}
}

func TestAgent_RunStopsWithContext(t *testing.T) {
	a, _ := newTestAgent(&fakeInventory{report: reportWith(t)}, &fakeControlPlane{}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestAgent_EscrowsWhatTheControlPlaneAsksFor(t *testing.T) {
	cp := &fakeControlPlane{}
	esc := &recordingEscrow{}
	a := New(Options{
		Inventory:    &fakeInventory{report: reportWith(t)},
		ControlPlane: cp,
		Interval:     15 * time.Second,
		Commands:     []string{protocol.CommandKeysRestore},
		Escrow:       esc,
		Logger:       slog.New(slog.DiscardHandler),
	})
	a.cycle(context.Background())
	if len(esc.got) != 0 {
		t.Fatalf("escrowed without being asked: %v", esc.got)
	}
	cp.escrow = []string{"SHA256:a"}
	a.cycle(context.Background())
	if len(esc.got) != 1 || esc.got[0][0] != "SHA256:a" {
		t.Fatalf("escrow calls = %v", esc.got)
	}
	if got := cp.got[1].Commands; len(got) != 1 || got[0] != protocol.CommandKeysRestore {
		t.Fatalf("check-in commands = %v", got)
	}
}

type recordingLoader struct{ active []string }

func (r *recordingLoader) LoadRestored(_ context.Context, active string) {
	r.active = append(r.active, active)
}

// While restored keys are not loaded, each cycle retries the restart.
func TestAgent_LoadsPendingRestoredKeys(t *testing.T) {
	report := reportWith(t)
	inv := &fakeInventory{report: report}
	loader := &recordingLoader{}
	a := New(Options{
		Inventory: inv, ControlPlane: &fakeControlPlane{}, Interval: 15 * time.Second,
		Loader: loader, Logger: slog.New(slog.DiscardHandler),
	})
	a.cycle(context.Background())
	if len(loader.active) != 0 {
		t.Fatal("restarted with nothing pending")
	}
	inv.report.Pending = []string{"SHA256:restored"}
	a.cycle(context.Background())
	if len(loader.active) != 1 || loader.active[0] != report.Controller.ActiveFingerprint {
		t.Fatalf("loader calls = %v", loader.active)
	}
}

// A check-in reporting more than protocol.MaxKeys keys is refused, so the
// agent warns well before.
func TestAgent_WarnsAsKeysNearTheLimit(t *testing.T) {
	report := reportWith(t)
	a, logs := newTestAgent(&fakeInventory{report: report}, &fakeControlPlane{}, nil)
	for _, n := range []int{keysWarnAt - 1, keysWarnAt, keysWarnAt, protocol.MaxKeys + 1} {
		a.noteKeyCount(context.Background(), n)
	}
	if got := strings.Count(logs.String(), "event=controller.many_keys"); got != 1 {
		t.Errorf("many_keys warnings = %d, want 1:\n%s", got, logs)
	}
	if !strings.Contains(logs.String(), "event=controller.too_many_keys") {
		t.Errorf("no too_many_keys error:\n%s", logs)
	}
}

// With every capability off the agent still checks in with its
// controller's active key.
func TestAgent_ChecksInWithoutCapabilities(t *testing.T) {
	cp := &fakeControlPlane{}
	report := reportWith(t)
	report.Complete = false
	a := New(Options{Inventory: &fakeInventory{report: report}, ControlPlane: cp, Interval: 15 * time.Second, Logger: slog.New(slog.DiscardHandler)})
	a.cycle(context.Background())
	if len(cp.got) != 1 {
		t.Fatalf("check-ins = %d", len(cp.got))
	}
	in := cp.got[0]
	if in.Capabilities == nil || len(in.Capabilities) != 0 || in.Commands == nil || len(in.Keys) != 1 {
		t.Fatalf("check-in = %+v", in)
	}
}
