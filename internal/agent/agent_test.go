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
	mu   sync.Mutex
	got  []protocol.CheckIn
	errs []error
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
	return &protocol.CheckInResponse{NextCheckInSeconds: 15}, nil
}

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
