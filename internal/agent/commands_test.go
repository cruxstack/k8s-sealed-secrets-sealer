package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
)

// queueClient hands out queued commands once and records results.
type queueClient struct {
	mu      sync.Mutex
	queue   []protocol.Command
	results map[string]protocol.CommandResult
	polls   int
}

func (q *queueClient) Commands(ctx context.Context, _ time.Duration) ([]protocol.Command, error) {
	q.mu.Lock()
	q.polls++
	out := q.queue
	q.queue = nil
	q.mu.Unlock()
	if len(out) == 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	return out, nil
}

func (q *queueClient) Result(_ context.Context, id string, res protocol.CommandResult) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.results[id] = res
	return nil
}

func (q *queueClient) result(id string) (protocol.CommandResult, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	r, ok := q.results[id]
	return r, ok
}

func TestCommands_RunsHandlersAndReports(t *testing.T) {
	now := time.Now()
	q := &queueClient{results: map[string]protocol.CommandResult{}, queue: []protocol.Command{
		{ID: "ok", Type: protocol.CommandRenewalEnable, ExpiresAt: now.Add(time.Minute), Payload: json.RawMessage(`{"period":"720h"}`)},
		{ID: "fails", Type: protocol.CommandKeysRestore, ExpiresAt: now.Add(time.Minute), Payload: json.RawMessage(`{}`)},
		{ID: "unknown", Type: "exec.v1", ExpiresAt: now.Add(time.Minute)},
		{ID: "expired", Type: protocol.CommandRenewalEnable, ExpiresAt: now.Add(-time.Second)},
	}}
	c := NewCommands(q, nil, nil)
	var ran []string
	c.Handle(protocol.CommandRenewalEnable, func(_ context.Context, cmd protocol.Command) (any, error) {
		ran = append(ran, cmd.ID+" "+string(cmd.Payload))
		return map[string]string{"period": "720h0m0s"}, nil
	})
	c.Handle(protocol.CommandKeysRestore, func(context.Context, protocol.Command) (any, error) {
		return protocol.KeysRestoreResult{Failed: []protocol.KeyFailure{{Fingerprint: "SHA256:x", Error: "boom"}}}, errors.New(strings.Repeat("e", 2000))
	})
	if got := c.Types(); !slices.Equal(got, []string{protocol.CommandKeysRestore, protocol.CommandRenewalEnable}) {
		t.Fatalf("Types = %v", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, ok := q.result("unknown"); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("commands were not run")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	if r, _ := q.result("ok"); r.Status != protocol.CommandSucceeded || string(r.Result) != `{"period":"720h0m0s"}` || !slices.Equal(ran, []string{`ok {"period":"720h"}`}) {
		t.Errorf("ok = %+v", r)
	}
	if r, _ := q.result("fails"); r.Status != protocol.CommandFailed || len(r.Error) != maxErrorLen || !strings.Contains(string(r.Result), "boom") {
		t.Errorf("fails = %+v", r)
	}
	if r, _ := q.result("unknown"); r.Status != protocol.CommandFailed || r.Error != "unsupported command type" {
		t.Errorf("unknown = %+v", r)
	}
	// an expired command is neither run nor reported: the control plane
	// accepts no result after expiry
	if r, ok := q.result("expired"); ok || len(ran) != 1 {
		t.Errorf("expired = %+v (reported %v), ran = %v", r, ok, ran)
	}
}

// A command that ran until it expired has no result to report: the control
// plane would refuse it.
func TestCommands_DropsResultsOfExpiredCommands(t *testing.T) {
	f := &flakyResults{queueClient: queueClient{results: map[string]protocol.CommandResult{}}}
	c := NewCommands(f, nil, nil)
	c.Handle(protocol.CommandSeal, func(ctx context.Context, _ protocol.Command) (any, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	c.execute(context.Background(), context.Background(), protocol.Command{ID: "c", Type: protocol.CommandSeal, ExpiresAt: time.Now().Add(20 * time.Millisecond)})
	if n := f.attempts.Load(); n != 0 {
		t.Fatalf("reported an expired command's result %d times", n)
	}
}

func TestCommands_IdleWithoutHandlers(t *testing.T) {
	q := &queueClient{results: map[string]protocol.CommandResult{}}
	c := NewCommands(q, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if q.polls != 0 {
		t.Errorf("polled %d times with no handlers", q.polls)
	}
}

// heldPoll is a control plane whose poll returns only when released, like a
// long poll that leases a command after the agent was told to stop.
type heldPoll struct {
	inFlight chan struct{}
	release  chan []protocol.Command
	mu       sync.Mutex
	results  map[string]protocol.CommandResult
}

func (h *heldPoll) Commands(ctx context.Context, _ time.Duration) ([]protocol.Command, error) {
	select {
	case h.inFlight <- struct{}{}:
	default:
	}
	select {
	case cmds := <-h.release:
		return cmds, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (h *heldPoll) Result(ctx context.Context, id string, res protocol.CommandResult) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.results[id] = res
	return nil
}

// On shutdown a command leased by the poll in flight is still run and its
// result reported: once leased it is gone from the queue.
func TestCommands_FinishesTheCommandInFlightOnShutdown(t *testing.T) {
	h := &heldPoll{inFlight: make(chan struct{}, 1), release: make(chan []protocol.Command), results: map[string]protocol.CommandResult{}}
	c := NewCommands(h, nil, nil)
	var runErr error
	c.Handle(protocol.CommandSeal, func(ctx context.Context, _ protocol.Command) (any, error) {
		time.Sleep(20 * time.Millisecond)
		runErr = ctx.Err()
		return map[string]string{"ok": "yes"}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()

	<-h.inFlight
	cancel()
	h.release <- []protocol.Command{{ID: "seal", Type: protocol.CommandSeal, ExpiresAt: time.Now().Add(time.Minute)}}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the command in flight")
	}
	if runErr != nil {
		t.Fatalf("the command ran with a cancelled context: %v", runErr)
	}
	if r, ok := h.results["seal"]; !ok || r.Status != protocol.CommandSucceeded {
		t.Fatalf("result = %+v, reported %v", r, ok)
	}
}

// The grace period bounds shutdown: a command still running then is
// cancelled.
func TestCommands_ShutdownGraceIsBounded(t *testing.T) {
	h := &heldPoll{inFlight: make(chan struct{}, 1), release: make(chan []protocol.Command), results: map[string]protocol.CommandResult{}}
	c := NewCommands(h, nil, nil)
	c.grace = 50 * time.Millisecond
	c.Handle(protocol.CommandSeal, func(ctx context.Context, _ protocol.Command) (any, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	<-h.inFlight
	h.release <- []protocol.Command{{ID: "slow", Type: protocol.CommandSeal, ExpiresAt: time.Now().Add(time.Minute)}}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run outlived its grace period")
	}
}

// Commands still running or not yet run when the grace period ends are
// reported as failed, so the control plane need not wait for them to
// expire.
func TestCommands_ReportsUnfinishedCommandsAtShutdown(t *testing.T) {
	h := &heldPoll{inFlight: make(chan struct{}, 1), release: make(chan []protocol.Command), results: map[string]protocol.CommandResult{}}
	c := NewCommands(h, nil, nil)
	c.grace = 50 * time.Millisecond
	c.shutdownReport = time.Second
	ran := 0
	c.Handle(protocol.CommandSeal, func(ctx context.Context, _ protocol.Command) (any, error) {
		ran++
		<-ctx.Done()
		return nil, ctx.Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	<-h.inFlight
	expires := time.Now().Add(time.Minute)
	h.release <- []protocol.Command{
		{ID: "slow", Type: protocol.CommandSeal, ExpiresAt: expires},
		{ID: "next", Type: protocol.CommandSeal, ExpiresAt: expires},
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run outlived its grace period")
	}
	if ran != 1 {
		t.Errorf("ran %d commands after the grace period ended, want only the one in flight", ran)
	}
	for _, id := range []string{"slow", "next"} {
		r, ok := h.results[id]
		if !ok || r.Status != protocol.CommandFailed || !strings.HasPrefix(r.Error, errShutDown) {
			t.Errorf("%s = %+v, reported %v", id, r, ok)
		}
	}
}

// flakyResults fails Result with errs, in order, then accepts.
type flakyResults struct {
	queueClient
	errs     []error
	attempts atomic.Int32
}

func (f *flakyResults) Result(ctx context.Context, id string, res protocol.CommandResult) error {
	n := int(f.attempts.Add(1)) - 1
	if n < len(f.errs) {
		return f.errs[n]
	}
	return f.queueClient.Result(ctx, id, res)
}

func TestCommands_RetriesReportingAResult(t *testing.T) {
	unreachable := &statusError{code: http.StatusBadGateway}
	cases := map[string]struct {
		errs     []error
		attempts int32
		reported bool
	}{
		"control plane failing": {errs: []error{unreachable, unreachable}, attempts: 3, reported: true},
		"result refused":        {errs: []error{&statusError{code: http.StatusConflict}}, attempts: 1},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := &flakyResults{queueClient: queueClient{results: map[string]protocol.CommandResult{}}, errs: tc.errs}
			c := NewCommands(f, nil, nil)
			c.resultRetry = time.Millisecond
			c.Handle(protocol.CommandSeal, func(context.Context, protocol.Command) (any, error) { return nil, nil })
			c.execute(context.Background(), context.Background(), protocol.Command{ID: "c", Type: protocol.CommandSeal, ExpiresAt: time.Now().Add(time.Minute)})
			if got := f.attempts.Load(); got != tc.attempts {
				t.Errorf("attempts = %d, want %d", got, tc.attempts)
			}
			if _, ok := f.result("c"); ok != tc.reported {
				t.Errorf("reported = %v, want %v", ok, tc.reported)
			}
		})
	}
}

// Commands expire in the control plane's time: a clock running fast must
// not expire them.
func TestCommands_ExpiryUsesTheControlPlanesClock(t *testing.T) {
	// this agent's clock is 10 minutes ahead of the control plane's
	cpNow := time.Now().Add(-10 * time.Minute)
	q := &queueClient{results: map[string]protocol.CommandResult{}}
	c := NewCommands(q, nil, func() time.Time { return cpNow })
	ran := false
	c.Handle(protocol.CommandSeal, func(ctx context.Context, _ protocol.Command) (any, error) {
		ran = true
		if dl, ok := ctx.Deadline(); !ok || time.Until(dl) > 2*time.Minute || time.Until(dl) < time.Minute {
			t.Errorf("deadline = %v, want about two minutes from now", dl)
		}
		return nil, nil
	})
	// by this agent's own clock it expired 8 minutes ago
	c.execute(context.Background(), context.Background(), protocol.Command{ID: "c", Type: protocol.CommandSeal, ExpiresAt: cpNow.Add(2 * time.Minute)})
	if r, _ := q.result("c"); !ran || r.Status != protocol.CommandSucceeded {
		t.Fatalf("ran = %v, result = %+v", ran, r)
	}
}

// A handler that panics fails its command; the agent carries on.
func TestCommands_RecoversFromAPanic(t *testing.T) {
	q := &queueClient{results: map[string]protocol.CommandResult{}}
	c := NewCommands(q, nil, nil)
	c.Handle(protocol.CommandSeal, func(context.Context, protocol.Command) (any, error) {
		panic("boom")
	})
	c.execute(context.Background(), context.Background(), protocol.Command{ID: "c", Type: protocol.CommandSeal, ExpiresAt: time.Now().Add(time.Minute)})
	if r, _ := q.result("c"); r.Status != protocol.CommandFailed || strings.Contains(r.Error, "boom") {
		t.Fatalf("result = %+v", r)
	}
}

// emptyAtOnce answers every poll at once with nothing.
type emptyAtOnce struct{ polls atomic.Int32 }

func (e *emptyAtOnce) Commands(context.Context, time.Duration) ([]protocol.Command, error) {
	e.polls.Add(1)
	return nil, nil
}

func (e *emptyAtOnce) Result(context.Context, string, protocol.CommandResult) error { return nil }

// A control plane that does not hold the poll must not turn it into a busy
// loop.
func TestCommands_PacesEmptyPolls(t *testing.T) {
	e := &emptyAtOnce{}
	c := NewCommands(e, nil, nil)
	c.Handle(protocol.CommandSeal, func(context.Context, protocol.Command) (any, error) { return nil, nil })
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_ = c.Run(ctx)
	if n := e.polls.Load(); n > 2 {
		t.Fatalf("polled %d times in 300ms", n)
	}
}
